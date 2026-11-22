// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
)

// Block versions this library accepts: 3 is datalog v3.0, 4 is datalog v3.1,
// 5 is datalog v3.2, 6 is datalog v3.3.
const MinSchemaVersion uint32 = 3
const MaxSchemaVersion uint32 = 6

// Block versions, by the datalog release that introduced them.
const (
	blockVersion3_0 uint32 = 3
	blockVersion3_1 uint32 = 4
	// blockVersion3_2 is the minimum for a third-party block.
	blockVersion3_2 uint32 = 5
	blockVersion3_3 uint32 = 6
)

// v33Features selects the datalog v3.3 features that make a block a v3.3
// block.
type v33Features bool

const (
	// allV33Features is every feature of datalog v3.3: a block that this
	// library builds declares version 6 when it uses one of them.
	allV33Features v33Features = true
	// rustV33Features leaves out arrays, maps, .get() and .try_or(), which
	// biscuit-rust does not count when it computes the version of a block:
	// it writes arrays, maps and .get() in blocks of version 3 to 5, and
	// these must be read. The receiver of .try_or() is a closure, which it
	// counts.
	rustV33Features v33Features = false
)

// schemaVersion is the lowest block version able to carry the given content:
// the version that a new block declares.
func schemaVersion(facts datalog.FactSet, scopes []datalog.Scope, rules []datalog.Rule, checks []datalog.Check) uint32 {
	return requiredVersion(allV33Features, facts, scopes, rules, checks)
}

// readableVersion is the lowest version that a block read from a token must
// declare for its content. It asks for no more than biscuit-rust declares.
func readableVersion(facts datalog.FactSet, scopes []datalog.Scope, rules []datalog.Rule, checks []datalog.Check) uint32 {
	return requiredVersion(rustV33Features, facts, scopes, rules, checks)
}

func requiredVersion(v33 v33Features, facts datalog.FactSet, scopes []datalog.Scope, rules []datalog.Rule, checks []datalog.Check) uint32 {
	for _, f := range facts {
		if v33.inPredicate(f.Predicate) {
			return blockVersion3_3
		}
	}
	for _, c := range checks {
		if c.Kind == datalog.CheckKindReject {
			return blockVersion3_3
		}
		for _, q := range c.Queries {
			if v33.inRule(q) {
				return blockVersion3_3
			}
		}
	}
	for _, r := range rules {
		if v33.inRule(r) {
			return blockVersion3_3
		}
	}
	if hasScopes(scopes, rules, checks) {
		return blockVersion3_1
	}
	for _, c := range checks {
		if c.Kind != datalog.CheckKindOne {
			return blockVersion3_1
		}
		for _, q := range c.Queries {
			if containsV31Op(q.Expressions) {
				return blockVersion3_1
			}
		}
	}
	for _, r := range rules {
		if containsV31Op(r.Expressions) {
			return blockVersion3_1
		}
	}
	return blockVersion3_0
}

// inRule reports whether a rule uses a datalog v3.3 feature in its
// predicates or expressions.
func (v33 v33Features) inRule(r datalog.Rule) bool {
	if v33.inPredicate(r.Head) {
		return true
	}
	for _, p := range r.Body {
		if v33.inPredicate(p) {
			return true
		}
	}
	return v33.inExpressions(r.Expressions)
}

// inPredicate reports whether a predicate holds a term type introduced in
// datalog v3.3.
func (v33 v33Features) inPredicate(p datalog.Predicate) bool {
	for _, t := range p.Terms {
		if v33.isTerm(t) {
			return true
		}
	}
	return false
}

// isTerm reports whether a term has a type introduced in datalog v3.3:
// null, also as an element of a set, and arrays and maps.
func (v33 v33Features) isTerm(t datalog.Term) bool {
	switch t := t.(type) {
	case datalog.Null:
		return true
	case datalog.Array, datalog.Map:
		return v33 == allV33Features
	case datalog.Set:
		for _, e := range t {
			if v33.isTerm(e) {
				return true
			}
		}
	}
	return false
}

// inExpressions reports whether an expression uses an operator or a term
// introduced in datalog v3.3.
func (v33 v33Features) inExpressions(expressions []datalog.Expression) bool {
	for _, e := range expressions {
		for _, op := range e {
			switch op := op.(type) {
			case datalog.Value:
				if v33.isTerm(op.ID) {
					return true
				}
			case datalog.Closure:
				return true
			case datalog.UnaryOp:
				switch op.UnaryOpFunc.Type() {
				case datalog.UnaryTypeOf, datalog.UnaryFfi:
					return true
				}
			case datalog.BinaryOp:
				switch op.BinaryOpFunc.Type() {
				case datalog.BinaryHeterogeneousEqual, datalog.BinaryHeterogeneousNotEqual,
					datalog.BinaryLazyAnd, datalog.BinaryLazyOr, datalog.BinaryAll, datalog.BinaryAny,
					datalog.BinaryFfi:
					return true
				case datalog.BinaryGet, datalog.BinaryTryOr:
					if v33 == allV33Features {
						return true
					}
				}
			}
		}
	}
	return false
}

// containsV31Op reports whether an expression uses an operator introduced
// in datalog v3.1: bitwise operators and !==.
func containsV31Op(expressions []datalog.Expression) bool {
	for _, e := range expressions {
		for _, op := range e {
			b, ok := op.(datalog.BinaryOp)
			if !ok {
				continue
			}
			switch b.BinaryOpFunc.Type() {
			case datalog.BinaryBitwiseAnd, datalog.BinaryBitwiseOr, datalog.BinaryBitwiseXor, datalog.BinaryNotEqual:
				return true
			}
		}
	}
	return false
}

// defaultSymbolTable predefines some symbols available in every implementation, to avoid
// transmitting them with every token
var defaultSymbolTable = &datalog.SymbolTable{}

type Block struct {
	symbols *datalog.SymbolTable
	// facts are the facts of the block as the block has them, in order. A
	// fact can be there more than once: the type is used as a list, and
	// FactSet.Insert, which keeps each fact once, is not used on it.
	facts  *datalog.FactSet
	rules  []datalog.Rule
	checks []datalog.Check
	// scopes is the block-level `trusting` clause, the default scope of
	// the rules and checks of the block.
	scopes []datalog.Scope
	// publicKeys are the keys the scopes of this block add to the key
	// table of the token.
	publicKeys []datalog.PublicKey
	// externalKey is the key a third party signed the block with; nil for
	// a first-party block. A third-party block has its own symbol and key
	// tables, which the token tables do not include.
	externalKey *datalog.PublicKey
	context     string
	version     uint32
}

// symbolTable is the table the content of the block refers to: the token's
// for a first-party block, the defaults plus its own for a third-party block.
func (b *Block) symbolTable(token *datalog.SymbolTable) *datalog.SymbolTable {
	if b.externalKey == nil {
		return token
	}
	symbols := defaultSymbolTable.Clone()
	appendSymbols(symbols, b.symbols)
	return symbols
}

// appendSymbols adds the symbols a block declares to table. The backing
// array of table is not written to, the caller may share it.
func appendSymbols(table, declared *datalog.SymbolTable) {
	*table = append((*table)[:len(*table):len(*table)], *declared...)
}

// checkNewSymbols verifies that the block declares only symbols that are
// new: not a default symbol, not a symbol of table (the symbols of the
// blocks before it, none for a third-party block), and not one that it
// declares two times. An implementation that does not add such a symbol
// again gives the symbols after it another index than one that does, so the
// block would not mean the same for both.
//
// biscuit-rust accepts a symbol that one block declares two times, and gives
// it two indexes. Its builders never write one.
func (b *Block) checkNewSymbols(table *datalog.SymbolTable) error {
	known := make(map[string]struct{}, len(datalog.DEFAULT_SYMBOLS)+table.Len()+b.symbols.Len())
	for _, s := range datalog.DEFAULT_SYMBOLS {
		known[s] = struct{}{}
	}
	for _, s := range *table {
		known[s] = struct{}{}
	}
	for _, s := range *b.symbols {
		if _, ok := known[s]; ok {
			return fmt.Errorf("%w: %q", ErrSymbolTableOverlap, s)
		}
		known[s] = struct{}{}
	}
	return nil
}

// checkSymbols verifies that the block only refers to symbols of the table
// given: the default symbols, those of the blocks before it and its own for
// a first-party block; the default symbols and its own for a third-party
// block. A symbol that only a later block defines is refused, or that block
// would decide what this one means.
func (b *Block) checkSymbols(symbols *datalog.SymbolTable) error {
	c := symbolChecker{symbols}
	for _, f := range *b.facts {
		if err := c.predicate(f.Predicate); err != nil {
			return err
		}
	}
	for _, r := range b.rules {
		if err := c.rule(r); err != nil {
			return err
		}
	}
	for _, check := range b.checks {
		for _, q := range check.Queries {
			if err := c.rule(q); err != nil {
				return err
			}
		}
	}
	return nil
}

// symbolChecker walks the content of a block looking for a reference to a
// symbol its table does not have: the name of a predicate, of a variable or
// of an extern function, or a string.
type symbolChecker struct {
	symbols *datalog.SymbolTable
}

func (c symbolChecker) symbol(index uint64) error {
	known := index < uint64(len(datalog.DEFAULT_SYMBOLS))
	if index >= uint64(datalog.OFFSET) {
		known = index-uint64(datalog.OFFSET) < uint64(c.symbols.Len())
	}
	if !known {
		return fmt.Errorf("%w: unknown symbol %d", ErrMissingSymbols, index)
	}
	return nil
}

func (c symbolChecker) rule(r datalog.Rule) error {
	if err := c.predicate(r.Head); err != nil {
		return err
	}
	for _, p := range r.Body {
		if err := c.predicate(p); err != nil {
			return err
		}
	}
	for _, e := range r.Expressions {
		if err := c.expression(e); err != nil {
			return err
		}
	}
	return nil
}

func (c symbolChecker) predicate(p datalog.Predicate) error {
	if err := c.symbol(uint64(p.Name)); err != nil {
		return err
	}
	return c.terms(p.Terms...)
}

func (c symbolChecker) terms(terms ...datalog.Term) error {
	for _, t := range terms {
		var err error
		switch t := t.(type) {
		case datalog.String:
			err = c.symbol(uint64(t))
		case datalog.Variable:
			err = c.symbol(uint64(t))
		case datalog.Set:
			err = c.terms(t...)
		case datalog.Array:
			err = c.terms(t...)
		case datalog.Map:
			for _, e := range t {
				if err = c.terms(e.Key, e.Value); err != nil {
					break
				}
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (c symbolChecker) expression(e datalog.Expression) error {
	for _, op := range e {
		var err error
		switch op := op.(type) {
		case datalog.Value:
			err = c.terms(op.ID)
		case datalog.Closure:
			for _, p := range op.Params {
				if err = c.symbol(uint64(p)); err != nil {
					break
				}
			}
			if err == nil {
				err = c.expression(op.Body)
			}
		case datalog.UnaryOp:
			if ffi, ok := op.UnaryOpFunc.(datalog.Ffi); ok {
				err = c.symbol(uint64(ffi.Name))
			}
		case datalog.BinaryOp:
			if ffi, ok := op.BinaryOpFunc.(datalog.FfiBinary); ok {
				err = c.symbol(uint64(ffi.Name))
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *Block) Code(symbols *datalog.SymbolTable) string {
	debug := &datalog.SymbolDebugger{
		SymbolTable: symbols,
	}
	facts := make([]string, len(*b.facts))
	for i, f := range *b.facts {
		facts[i] = debug.Predicate(f.Predicate)
	}
	rules := make([]string, len(b.rules))
	for i, r := range b.rules {
		rules[i] = debug.Rule(r)
	}

	checks := make([]string, len(b.checks))
	for i, c := range b.checks {
		checks[i] = debug.Check(c)
	}

	var scopes string
	if len(b.scopes) > 0 {
		scopes = strings.TrimPrefix(datalog.ScopesString(b.scopes), " ") + ";\n"
	}

	return fmt.Sprintf(`Block {
		%s%v
		%s
		%s
	}`,
		scopes,
		strings.Join(facts, ";\n"),
		strings.Join(rules, ";\n"),
		strings.Join(checks, ";\n"),
	)
}

func (b *Block) String(symbols *datalog.SymbolTable) string {
	debug := &datalog.SymbolDebugger{
		SymbolTable: symbols,
	}
	rules := make([]string, len(b.rules))
	for i, r := range b.rules {
		rules[i] = debug.Rule(r)
	}

	checks := make([]string, len(b.checks))
	for i, c := range b.checks {
		checks[i] = debug.Check(c)
	}

	return fmt.Sprintf(`Block {
		symbols: %+q
		context: %q
		facts: %v
		rules: %v
		checks: [%s]
		version: %d
	}`,
		*b.symbols,
		b.context,
		debug.FactSet(b.facts),
		rules,
		strings.Join(checks, ", "),
		b.version,
	)
}

type FactSet []Fact

func (fs FactSet) String() string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.String())
	}

	var outStr string
	if len(out) > 0 {
		outStr = fmt.Sprintf("\n\t%s\n", strings.Join(out, ",\n\t"))
	}

	return fmt.Sprintf("[%s]", outStr)
}

type ParsedBlock struct {
	Facts  FactSet
	Rules  []Rule
	Checks []Check
	Scopes []Scope
}

type ParsedAuthorizer struct {
	Policies []Policy
	Block    ParsedBlock
}

type Fact struct {
	Predicate
}

func (f Fact) convert(symbols *datalog.SymbolTable) datalog.Fact {
	return datalog.Fact{
		Predicate: f.Predicate.convert(symbols),
	}
}
func (f Fact) String() string {
	return f.Predicate.String()
}

func fromDatalogFact(symbols *datalog.SymbolTable, f datalog.Fact) (*Fact, error) {
	pred, err := fromDatalogPredicate(symbols, f.Predicate)
	if err != nil {
		return nil, err
	}

	return &Fact{
		Predicate: *pred,
	}, nil
}

func fromDatalogPredicate(symbols *datalog.SymbolTable, p datalog.Predicate) (*Predicate, error) {
	terms := make([]Term, 0, len(p.Terms))
	for _, id := range p.Terms {
		a, err := fromDatalogID(symbols, id)
		if err != nil {
			return nil, err
		}
		terms = append(terms, a)
	}

	return &Predicate{
		Name: symbols.Str(p.Name),
		IDs:  terms,
	}, nil
}

func fromDatalogID(symbols *datalog.SymbolTable, id datalog.Term) (Term, error) {
	var a Term
	switch id.Type() {
	case datalog.TermTypeVariable:
		a = Variable(symbols.Str(datalog.String(id.(datalog.Variable))))
	case datalog.TermTypeInteger:
		a = Integer(id.(datalog.Integer))
	case datalog.TermTypeString:
		a = String(symbols.Str(id.(datalog.String)))
	case datalog.TermTypeDate:
		a = Date(time.Unix(int64(id.(datalog.Date)), 0))
	case datalog.TermTypeBytes:
		a = Bytes(id.(datalog.Bytes))
	case datalog.TermTypeBool:
		a = Bool(id.(datalog.Bool))
	case datalog.TermTypeNull:
		a = Null{}
	case datalog.TermTypeArray:
		dlArray := id.(datalog.Array)
		array := make(Array, len(dlArray))
		for i, e := range dlArray {
			elt, err := fromDatalogID(symbols, e)
			if err != nil {
				return nil, err
			}
			array[i] = elt
		}
		a = array
	case datalog.TermTypeMap:
		dlMap := id.(datalog.Map)
		m := make(Map, len(dlMap))
		for i, e := range dlMap {
			key, err := fromDatalogID(symbols, e.Key)
			if err != nil {
				return nil, err
			}
			value, err := fromDatalogID(symbols, e.Value)
			if err != nil {
				return nil, err
			}
			m[i] = MapEntry{Key: key, Value: value}
		}
		a = m
	case datalog.TermTypeSet:
		setIDs := id.(datalog.Set)
		set := make(Set, 0, len(setIDs))
		for _, i := range setIDs {
			setTerm, err := fromDatalogID(symbols, i)
			if err != nil {
				return nil, err
			}
			set = append(set, setTerm)
		}
		a = set
	default:
		return nil, fmt.Errorf("unsupported term type: %v", id.Type())
	}

	return a, nil
}

type Rule struct {
	Head        Predicate
	Body        []Predicate
	Expressions []Expression
	// Scopes is the `trusting` clause; empty means the scopes of the block.
	Scopes []Scope
}

// validate returns ErrInvalidBlockRule if the head of the rule has a variable
// that no predicate of the body binds. Such a rule cannot generate a fact,
// and an authorizer refuses a token that has one.
func (r Rule) validate() error {
	bound := make(map[Variable]struct{})
	for _, p := range r.Body {
		for _, id := range p.IDs {
			if v, ok := id.(Variable); ok {
				bound[v] = struct{}{}
			}
		}
	}
	for _, id := range r.Head.IDs {
		if v, ok := id.(Variable); ok {
			if _, ok := bound[v]; !ok {
				return fmt.Errorf("%w: the body of the rule %q does not bind $%s", ErrInvalidBlockRule, r.Head.Name, string(v))
			}
		}
	}
	return nil
}

// convert gives the symbols of the rule in the order of biscuit-rust: the
// head, the body, then the expressions.
func (r Rule) convert(symbols *datalog.SymbolTable) datalog.Rule {
	head := r.Head.convert(symbols)

	dlBody := make([]datalog.Predicate, len(r.Body))
	for i, p := range r.Body {
		dlBody[i] = p.convert(symbols)
	}

	dlExpressions := make([]datalog.Expression, len(r.Expressions))
	for i, e := range r.Expressions {
		dlExpressions[i] = e.convert(symbols)
	}
	return datalog.Rule{
		Head:        head,
		Body:        dlBody,
		Expressions: dlExpressions,
		Scopes:      slices.Clone(r.Scopes),
	}
}

func fromDatalogRule(symbols *datalog.SymbolTable, dlRule datalog.Rule) (*Rule, error) {
	head, err := fromDatalogPredicate(symbols, dlRule.Head)
	if err != nil {
		return nil, fmt.Errorf("failed to convert datalog rule head: %v", err)
	}

	body := make([]Predicate, len(dlRule.Body))
	for i, dlPred := range dlRule.Body {
		pred, err := fromDatalogPredicate(symbols, dlPred)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog rule body: %v", err)
		}
		body[i] = *pred
	}

	expressions := make([]Expression, len(dlRule.Expressions))
	for i, dlExpr := range dlRule.Expressions {
		expr, err := fromDatalogExpression(symbols, dlExpr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog rule expression: %v", err)
		}
		expressions[i] = expr
	}

	return &Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
		Scopes:      slices.Clone(dlRule.Scopes),
	}, nil
}

type Expression []Op

func (e Expression) convert(symbols *datalog.SymbolTable) datalog.Expression {
	expr := make(datalog.Expression, len(e))
	for i, elt := range e {
		expr[i] = elt.convert(symbols)
	}
	return expr
}

func fromDatalogExpression(symbols *datalog.SymbolTable, dlExpr datalog.Expression) (Expression, error) {
	expr := make(Expression, len(dlExpr))
	for i, dlOP := range dlExpr {
		switch dlOP.Type() {
		case datalog.OpTypeValue:
			v, err := fromDatalogValueOp(symbols, dlOP.(datalog.Value))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog expression value: %w", err)
			}
			expr[i] = v
		case datalog.OpTypeUnary:
			u, err := fromDatalogUnaryOp(symbols, dlOP.(datalog.UnaryOp))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog unary expression: %w", err)
			}
			expr[i] = u
		case datalog.OpTypeBinary:
			b, err := fromDatalogBinaryOp(symbols, dlOP.(datalog.BinaryOp))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog binary expression: %w", err)
			}
			expr[i] = b
		case datalog.OpTypeClosure:
			c, err := fromDatalogClosure(symbols, dlOP.(datalog.Closure))
			if err != nil {
				return nil, err
			}
			expr[i] = c
		default:
			return nil, fmt.Errorf("unsupported datalog expression type: %v", dlOP.Type())
		}
	}
	return expr, nil
}

type Op interface {
	Type() OpType
	convert(symbols *datalog.SymbolTable) datalog.Op
}

type OpType byte

const (
	OpTypeValue OpType = iota
	OpTypeUnary
	OpTypeBinary
	// OpTypeClosure is datalog v3.3; using it makes the block version 6.
	OpTypeClosure
)

// Closure is an expression evaluated by the operator that consumes it, with
// Params bound by that operator: the right side of && and || (BinaryLazyAnd,
// BinaryLazyOr), the predicate of .all() and .any() (BinaryAll, BinaryAny),
// or the receiver of .try_or() (BinaryTryOr).
type Closure struct {
	Params []Variable
	Body   Expression
}

func (Closure) Type() OpType {
	return OpTypeClosure
}
func (c Closure) convert(symbols *datalog.SymbolTable) datalog.Op {
	params := make([]datalog.Variable, len(c.Params))
	for i, p := range c.Params {
		params[i] = p.convert(symbols).(datalog.Variable)
	}
	return datalog.Closure{Params: params, Body: c.Body.convert(symbols)}
}
func fromDatalogClosure(symbols *datalog.SymbolTable, dlClosure datalog.Closure) (Op, error) {
	params := make([]Variable, len(dlClosure.Params))
	for i, p := range dlClosure.Params {
		params[i] = Variable(symbols.Var(p))
	}
	body, err := fromDatalogExpression(symbols, dlClosure.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to convert datalog closure: %w", err)
	}
	return Closure{Params: params, Body: body}, nil
}

type Value struct {
	Term Term
}

func (v Value) Type() OpType {
	return OpTypeValue
}
func (v Value) convert(symbols *datalog.SymbolTable) datalog.Op {
	return datalog.Value{ID: v.Term.convert(symbols)}
}
func fromDatalogValueOp(symbols *datalog.SymbolTable, dlValue datalog.Value) (Op, error) {
	term, err := fromDatalogID(symbols, dlValue.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert datalog expression value: %v", err)
	}
	return Value{Term: term}, nil
}

type unaryOpType byte

type UnaryOp unaryOpType

const (
	UnaryUndefined UnaryOp = iota
	UnaryNegate
	UnaryParens
	UnaryLength
	// UnaryTypeOf is datalog v3.3; using it makes the block version 6.
	UnaryTypeOf
)

func (UnaryOp) Type() OpType {
	return OpTypeUnary
}
func (op UnaryOp) convert(symbols *datalog.SymbolTable) datalog.Op {
	switch op {
	case UnaryNegate:
		return datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}}
	case UnaryParens:
		return datalog.UnaryOp{UnaryOpFunc: datalog.Parens{}}
	case UnaryLength:
		return datalog.UnaryOp{UnaryOpFunc: datalog.Length{}}
	case UnaryTypeOf:
		return datalog.UnaryOp{UnaryOpFunc: datalog.TypeOf{}}
	default:
		panic(fmt.Sprintf("biscuit: cannot convert invalid unary op type: %v", op))
	}
}

func fromDatalogUnaryOp(symbols *datalog.SymbolTable, dlUnary datalog.UnaryOp) (Op, error) {
	switch dlUnary.UnaryOpFunc.Type() {
	case datalog.UnaryNegate:
		return UnaryNegate, nil
	case datalog.UnaryParens:
		return UnaryParens, nil
	case datalog.UnaryLength:
		return UnaryLength, nil
	case datalog.UnaryTypeOf:
		return UnaryTypeOf, nil
	case datalog.UnaryFfi:
		return ExternUnary{Name: symbols.Str(dlUnary.UnaryOpFunc.(datalog.Ffi).Name)}, nil
	default:
		return UnaryUndefined, fmt.Errorf("unsupported datalog unary op: %v", dlUnary.UnaryOpFunc.Type())
	}
}

// ExternUnary is the datalog v3.3 call `$value.extern::name()` of a function
// registered on the authorizer with WithExternFuncs; using it makes the block
// version 6.
type ExternUnary struct {
	Name string
}

func (ExternUnary) Type() OpType {
	return OpTypeUnary
}
func (op ExternUnary) convert(symbols *datalog.SymbolTable) datalog.Op {
	return datalog.UnaryOp{UnaryOpFunc: datalog.Ffi{Name: symbols.Insert(op.Name)}}
}

// ExternBinary is the datalog v3.3 call `$left.extern::name($right)` of a
// function registered on the authorizer with WithExternFuncs; using it makes
// the block version 6.
type ExternBinary struct {
	Name string
}

func (ExternBinary) Type() OpType {
	return OpTypeBinary
}
func (op ExternBinary) convert(symbols *datalog.SymbolTable) datalog.Op {
	return datalog.BinaryOp{BinaryOpFunc: datalog.FfiBinary{Name: symbols.Insert(op.Name)}}
}

type binaryOpType byte

type BinaryOp binaryOpType

const (
	BinaryUndefined BinaryOp = iota
	BinaryLessThan
	BinaryLessOrEqual
	BinaryGreaterThan
	BinaryGreaterOrEqual
	BinaryEqual
	BinaryContains
	BinaryPrefix
	BinarySuffix
	BinaryRegex
	BinaryAdd
	BinarySub
	BinaryMul
	BinaryDiv
	BinaryAnd
	BinaryOr
	BinaryIntersection
	BinaryUnion
	// Datalog v3.1 operators; using one makes the block version 4.
	BinaryBitwiseAnd
	BinaryBitwiseOr
	BinaryBitwiseXor
	BinaryNotEqual
	// Datalog v3.3 operators; using one makes the block version 6.
	BinaryHeterogeneousEqual
	BinaryHeterogeneousNotEqual
	BinaryLazyAnd
	BinaryLazyOr
	BinaryAll
	BinaryAny
	BinaryGet
	// BinaryTryOr is datalog v3.3; its receiver is a Closure without
	// parameters and its right operand the fallback value.
	BinaryTryOr
)

func (BinaryOp) Type() OpType {
	return OpTypeBinary
}
func (op BinaryOp) convert(symbols *datalog.SymbolTable) datalog.Op {
	switch op {
	case BinaryLessThan:
		return datalog.BinaryOp{BinaryOpFunc: datalog.LessThan{}}
	case BinaryLessOrEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}}
	case BinaryGreaterThan:
		return datalog.BinaryOp{BinaryOpFunc: datalog.GreaterThan{}}
	case BinaryGreaterOrEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}}
	case BinaryEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}}
	case BinaryContains:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}}
	case BinaryPrefix:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Prefix{}}
	case BinarySuffix:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Suffix{}}
	case BinaryRegex:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Regex{}}
	case BinaryAdd:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Add{}}
	case BinarySub:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Sub{}}
	case BinaryMul:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Mul{}}
	case BinaryDiv:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Div{}}
	case BinaryAnd:
		return datalog.BinaryOp{BinaryOpFunc: datalog.And{}}
	case BinaryOr:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Or{}}
	case BinaryIntersection:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Intersection{}}
	case BinaryUnion:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Union{}}
	case BinaryBitwiseAnd:
		return datalog.BinaryOp{BinaryOpFunc: datalog.BitwiseAnd{}}
	case BinaryBitwiseOr:
		return datalog.BinaryOp{BinaryOpFunc: datalog.BitwiseOr{}}
	case BinaryBitwiseXor:
		return datalog.BinaryOp{BinaryOpFunc: datalog.BitwiseXor{}}
	case BinaryNotEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.NotEqual{}}
	case BinaryHeterogeneousEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.HeterogeneousEqual{}}
	case BinaryHeterogeneousNotEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.HeterogeneousNotEqual{}}
	case BinaryLazyAnd:
		return datalog.BinaryOp{BinaryOpFunc: datalog.LazyAnd{}}
	case BinaryLazyOr:
		return datalog.BinaryOp{BinaryOpFunc: datalog.LazyOr{}}
	case BinaryAll:
		return datalog.BinaryOp{BinaryOpFunc: datalog.All{}}
	case BinaryAny:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Any{}}
	case BinaryGet:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Get{}}
	case BinaryTryOr:
		return datalog.BinaryOp{BinaryOpFunc: datalog.TryOr{}}
	default:
		panic(fmt.Sprintf("biscuit: cannot convert invalid binary op type: %v", op))
	}
}

func fromDatalogBinaryOp(symbols *datalog.SymbolTable, dbBinary datalog.BinaryOp) (Op, error) {
	switch dbBinary.BinaryOpFunc.Type() {
	case datalog.BinaryLessThan:
		return BinaryLessThan, nil
	case datalog.BinaryLessOrEqual:
		return BinaryLessOrEqual, nil
	case datalog.BinaryGreaterThan:
		return BinaryGreaterThan, nil
	case datalog.BinaryGreaterOrEqual:
		return BinaryGreaterOrEqual, nil
	case datalog.BinaryEqual:
		return BinaryEqual, nil
	case datalog.BinaryContains:
		return BinaryContains, nil
	case datalog.BinaryPrefix:
		return BinaryPrefix, nil
	case datalog.BinarySuffix:
		return BinarySuffix, nil
	case datalog.BinaryRegex:
		return BinaryRegex, nil
	case datalog.BinaryAdd:
		return BinaryAdd, nil
	case datalog.BinarySub:
		return BinarySub, nil
	case datalog.BinaryMul:
		return BinaryMul, nil
	case datalog.BinaryDiv:
		return BinaryDiv, nil
	case datalog.BinaryAnd:
		return BinaryAnd, nil
	case datalog.BinaryOr:
		return BinaryOr, nil
	case datalog.BinaryIntersection:
		return BinaryIntersection, nil
	case datalog.BinaryUnion:
		return BinaryUnion, nil
	case datalog.BinaryBitwiseAnd:
		return BinaryBitwiseAnd, nil
	case datalog.BinaryBitwiseOr:
		return BinaryBitwiseOr, nil
	case datalog.BinaryBitwiseXor:
		return BinaryBitwiseXor, nil
	case datalog.BinaryNotEqual:
		return BinaryNotEqual, nil
	case datalog.BinaryHeterogeneousEqual:
		return BinaryHeterogeneousEqual, nil
	case datalog.BinaryHeterogeneousNotEqual:
		return BinaryHeterogeneousNotEqual, nil
	case datalog.BinaryLazyAnd:
		return BinaryLazyAnd, nil
	case datalog.BinaryLazyOr:
		return BinaryLazyOr, nil
	case datalog.BinaryAll:
		return BinaryAll, nil
	case datalog.BinaryAny:
		return BinaryAny, nil
	case datalog.BinaryGet:
		return BinaryGet, nil
	case datalog.BinaryTryOr:
		return BinaryTryOr, nil
	case datalog.BinaryFfi:
		return ExternBinary{Name: symbols.Str(dbBinary.BinaryOpFunc.(datalog.FfiBinary).Name)}, nil
	default:
		return BinaryUndefined, fmt.Errorf("unsupported datalog binary op: %v", dbBinary.BinaryOpFunc.Type())
	}
}

// CheckKind selects how the queries of a Check are evaluated.
type CheckKind byte

const (
	// CheckKindOne (`check if`) passes when one query has at least one match.
	CheckKindOne CheckKind = iota
	// CheckKindAll (`check all`) passes when one query has at least one match
	// and every match of that query satisfies its expressions. Requires a
	// datalog v3.1 block (version 4).
	CheckKindAll
	// CheckKindReject (`reject if`) passes when no query has a match.
	// Requires a datalog v3.3 block (version 6).
	CheckKindReject
)

func (k CheckKind) convert() datalog.CheckKind {
	switch k {
	case CheckKindAll:
		return datalog.CheckKindAll
	case CheckKindReject:
		return datalog.CheckKindReject
	default:
		return datalog.CheckKindOne
	}
}

func fromDatalogCheckKind(k datalog.CheckKind) CheckKind {
	switch k {
	case datalog.CheckKindAll:
		return CheckKindAll
	case datalog.CheckKindReject:
		return CheckKindReject
	default:
		return CheckKindOne
	}
}

type Check struct {
	Queries []Rule
	Kind    CheckKind
}

func (c Check) convert(symbols *datalog.SymbolTable) datalog.Check {
	queries := make([]datalog.Rule, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = q.convert(symbols)
	}

	return datalog.Check{
		Queries: queries,
		Kind:    c.Kind.convert(),
	}
}

func fromDatalogCheck(symbols *datalog.SymbolTable, dlCheck datalog.Check) (*Check, error) {
	queries := make([]Rule, len(dlCheck.Queries))
	for i, q := range dlCheck.Queries {
		query, err := fromDatalogRule(symbols, q)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog check query: %w", err)
		}
		queries[i] = *query
	}

	return &Check{
		Queries: queries,
		Kind:    fromDatalogCheckKind(dlCheck.Kind),
	}, nil
}

type Predicate struct {
	Name string
	IDs  []Term
}

// convert gives the name its symbol before the terms, as biscuit-rust does.
func (p Predicate) convert(symbols *datalog.SymbolTable) datalog.Predicate {
	name := symbols.Insert(p.Name)
	var ids []datalog.Term
	for _, a := range p.IDs {
		ids = append(ids, a.convert(symbols))
	}

	return datalog.Predicate{
		Name:  name,
		Terms: ids,
	}
}
func (p Predicate) String() string {
	terms := make([]string, 0, len(p.IDs))
	for _, a := range p.IDs {
		terms = append(terms, a.String())
	}
	return fmt.Sprintf("%s(%s)", p.Name, strings.Join(terms, ", "))
}

type TermType byte

const (
	TermTypeSymbol TermType = iota
	TermTypeVariable
	TermTypeInteger
	TermTypeString
	TermTypeDate
	TermTypeBytes
	TermTypeBool
	TermTypeSet
	// TermTypeNull, TermTypeArray and TermTypeMap are datalog v3.3; using
	// them makes the block version 6.
	TermTypeNull
	TermTypeArray
	TermTypeMap
)

type Term interface {
	Type() TermType
	String() string
	convert(symbols *datalog.SymbolTable) datalog.Term
}

type Variable string

func (a Variable) Type() TermType { return TermTypeVariable }
func (a Variable) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Variable(symbols.Insert(string(a)))
}
func (a Variable) String() string { return fmt.Sprintf("$%s", string(a)) }

type Integer int64

func (a Integer) Type() TermType { return TermTypeInteger }
func (a Integer) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Integer(a)
}
func (a Integer) String() string { return fmt.Sprintf("%d", a) }

type String string

func (a String) Type() TermType { return TermTypeString }
func (a String) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.String(symbols.Insert(string(a)))
}

func (a String) String() string { return datalog.Quote(string(a)) }

type Date time.Time

func (a Date) Type() TermType { return TermTypeDate }
func (a Date) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Date(time.Time(a).Unix())
}
func (a Date) String() string { return time.Time(a).UTC().Format(time.RFC3339) }

type Bytes []byte

func (a Bytes) Type() TermType { return TermTypeBytes }
func (a Bytes) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Bytes(a)
}
func (a Bytes) String() string { return fmt.Sprintf("hex:%s", hex.EncodeToString(a)) }

type Bool bool

func (b Bool) Type() TermType { return TermTypeBool }
func (b Bool) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Bool(b)
}
func (b Bool) String() string { return fmt.Sprintf("%t", b) }

// Null is the absence of a value (datalog v3.3).
type Null struct{}

func (Null) Type() TermType { return TermTypeNull }
func (Null) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Null{}
}
func (Null) String() string { return "null" }

type Set []Term

func (a Set) Type() TermType { return TermTypeSet }

// canonical returns the elements as biscuit-rust keeps a set: in the order
// of their value, a string by its text, each element once.
func (a Set) canonical() Set {
	sorted := slices.Clone(a)
	slices.SortStableFunc(sorted, compareTerms)
	return slices.CompactFunc(sorted, func(x, y Term) bool { return compareTerms(x, y) == 0 })
}

// convert gives the elements their symbols in the order in which
// biscuit-rust keeps a set, so that the same source gives the same symbol
// table.
func (a Set) convert(symbols *datalog.SymbolTable) datalog.Term {
	sorted := a.canonical()
	elements := make([]datalog.Term, len(sorted))
	for i, e := range sorted {
		elements[i] = e.convert(symbols)
	}
	return datalog.NewSet(elements...)
}

// String prints the set as the block has it: see canonical.
func (a Set) String() string {
	if len(a) == 0 {
		return "{,}"
	}
	sorted := a.canonical()
	elts := make([]string, 0, len(sorted))
	for _, e := range sorted {
		elts = append(elts, e.String())
	}
	return fmt.Sprintf("{%s}", strings.Join(elts, ", "))
}

// compareTerms orders terms as biscuit-rust orders the terms of a builder:
// by type, in the order of the TermType values, then by value. A string has
// the order of its text. The datalog package has the same function for its
// own terms, where a string has the order of its symbol: the two must stay
// the same in all other points.
func compareTerms(a, b Term) int {
	if c := cmp.Compare(a.Type(), b.Type()); c != 0 {
		return c
	}
	switch a := a.(type) {
	case Variable:
		if b, ok := b.(Variable); ok {
			return cmp.Compare(a, b)
		}
	case Integer:
		if b, ok := b.(Integer); ok {
			return cmp.Compare(a, b)
		}
	case String:
		if b, ok := b.(String); ok {
			return cmp.Compare(a, b)
		}
	case Date:
		if b, ok := b.(Date); ok {
			return cmp.Compare(uint64(time.Time(a).Unix()), uint64(time.Time(b).Unix()))
		}
	case Bytes:
		if b, ok := b.(Bytes); ok {
			return bytes.Compare(a, b)
		}
	case Bool:
		if b, ok := b.(Bool); ok && a != b {
			if b {
				return -1
			}
			return 1
		}
	case Set:
		if b, ok := b.(Set); ok {
			x, y := slices.Clone(a), slices.Clone(b)
			slices.SortStableFunc(x, compareTerms)
			slices.SortStableFunc(y, compareTerms)
			return slices.CompareFunc(x, y, compareTerms)
		}
	case Array:
		if b, ok := b.(Array); ok {
			return slices.CompareFunc(a, b, compareTerms)
		}
	case Map:
		if b, ok := b.(Map); ok {
			x, y := slices.Clone(a), slices.Clone(b)
			byKey := func(e, f MapEntry) int { return compareTerms(e.Key, f.Key) }
			slices.SortStableFunc(x, byKey)
			slices.SortStableFunc(y, byKey)
			return slices.CompareFunc(x, y, func(e, f MapEntry) int {
				if c := compareTerms(e.Key, f.Key); c != 0 {
					return c
				}
				return compareTerms(e.Value, f.Value)
			})
		}
	}
	return 0
}

// Array is an ordered sequence of terms of any type (datalog v3.3).
type Array []Term

func (a Array) Type() TermType { return TermTypeArray }
func (a Array) convert(symbols *datalog.SymbolTable) datalog.Term {
	array := make(datalog.Array, len(a))
	for i, e := range a {
		array[i] = e.convert(symbols)
	}
	return array
}
func (a Array) String() string {
	elts := make([]string, len(a))
	for i, e := range a {
		elts[i] = e.String()
	}
	return fmt.Sprintf("[%s]", strings.Join(elts, ", "))
}

// MapEntry is one key/value pair of a Map; the key is an Integer or a String.
type MapEntry struct {
	Key   Term
	Value Term
}

// Map associates Integer or String keys with terms of any type (datalog
// v3.3). Entry order does not matter; a key given twice keeps its last value.
type Map []MapEntry

func (m Map) Type() TermType { return TermTypeMap }

// canonical returns the entries as biscuit-rust keeps a map: integer keys
// by value, then string keys by text. A key given twice keeps its last
// value.
func (m Map) canonical() Map {
	sorted := slices.Clone(m)
	slices.SortStableFunc(sorted, func(a, b MapEntry) int { return compareTerms(a.Key, b.Key) })
	entries := sorted[:0]
	for i, e := range sorted {
		if i+1 < len(sorted) && compareTerms(e.Key, sorted[i+1].Key) == 0 {
			continue
		}
		entries = append(entries, e)
	}
	return entries
}

// convert gives the keys and the values their symbols in the order in which
// biscuit-rust keeps a map, so that the same source gives the same symbol
// table.
func (m Map) convert(symbols *datalog.SymbolTable) datalog.Term {
	sorted := m.canonical()
	entries := make([]datalog.MapEntry, len(sorted))
	for i, e := range sorted {
		entries[i] = datalog.MapEntry{Key: e.Key.convert(symbols), Value: e.Value.convert(symbols)}
	}
	return datalog.NewMap(entries...)
}

// String prints the map as the block has it: see canonical.
func (m Map) String() string {
	sorted := m.canonical()
	entries := make([]string, len(sorted))
	for i, e := range sorted {
		entries[i] = fmt.Sprintf("%s: %s", e.Key, e.Value)
	}
	return fmt.Sprintf("{%s}", strings.Join(entries, ", "))
}

type PolicyKind byte

const (
	PolicyKindAllow = iota
	PolicyKindDeny
)

var (
	// DefaultAllowPolicy allows the biscuit to verify sucessfully as long as all its checks generate some facts.
	DefaultAllowPolicy = Policy{Kind: PolicyKindAllow, Queries: []Rule{{Head: Predicate{Name: "allow"}}}}
	// DefaultDenyPolicy makes the biscuit verification fail in all cases.
	DefaultDenyPolicy = Policy{Kind: PolicyKindDeny, Queries: []Rule{{Head: Predicate{Name: "deny"}}}}
)

type Policy struct {
	Queries []Rule
	Kind    PolicyKind
}
