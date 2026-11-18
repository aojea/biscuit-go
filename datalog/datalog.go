// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"
)

type TermType byte

const (
	TermTypeVariable TermType = iota
	TermTypeInteger
	TermTypeString
	TermTypeDate
	TermTypeBytes
	TermTypeBool
	TermTypeSet
	// TermTypeNull, TermTypeArray and TermTypeMap are datalog v3.3.
	TermTypeNull
	TermTypeArray
	TermTypeMap
)

// Term is a value in a predicate. Implementations are value types and
// Equal compares by value, using a type assertion on the concrete type.
// Do not store a pointer to a term (such as *Bytes) in a Term: the
// pointer would still satisfy the interface, but Equal would not match it.
type Term interface {
	Type() TermType
	Equal(Term) bool
	String() string
}

// Keep the value types implementing Term; a pointer receiver on any of them would break Equal.
var (
	_ Term = Variable(0)
	_ Term = Integer(0)
	_ Term = String(0)
	_ Term = Date(0)
	_ Term = Bytes(nil)
	_ Term = Bool(false)
	_ Term = Set(nil)
	_ Term = Null{}
	_ Term = Array(nil)
	_ Term = Map(nil)
)

type Set []Term

func (Set) Type() TermType { return TermTypeSet }

// Bytes is a slice and cannot be a map key, so look up elements with Equal.
func (s Set) contains(t Term) bool {
	for _, e := range s {
		if e.Equal(t) {
			return true
		}
	}
	return false
}

func (s Set) Equal(t Term) bool {
	c, ok := t.(Set)
	if !ok || len(c) != len(s) {
		return false
	}

	// Both directions: a duplicate on one side could otherwise hide a missing element.
	for _, e := range s {
		if !c.contains(e) {
			return false
		}
	}
	for _, e := range c {
		if !s.contains(e) {
			return false
		}
	}
	return true
}
func (s Set) String() string {
	eltStr := make([]string, 0, len(s))
	for _, e := range s {
		eltStr = append(eltStr, e.String())
	}
	if len(eltStr) == 0 {
		return "{,}"
	}
	sort.Strings(eltStr)
	return fmt.Sprintf("{%s}", strings.Join(eltStr, ", "))
}
func (s Set) Intersect(t Set) Set {
	result := Set{}

	for _, e := range s {
		if t.contains(e) {
			result = append(result, e)
		}
	}
	return result
}
func (s Set) Union(t Set) Set {
	result := Set{}
	result = append(result, s...)

	for _, e := range t {
		if !s.contains(e) {
			result = append(result, e)
		}
	}

	return result
}

type Variable uint32

func (Variable) Type() TermType      { return TermTypeVariable }
func (v Variable) Equal(t Term) bool { c, ok := t.(Variable); return ok && v == c }
func (v Variable) String() string {
	return fmt.Sprintf("$%d", v)
}

type Integer int64

func (Integer) Type() TermType      { return TermTypeInteger }
func (i Integer) Equal(t Term) bool { c, ok := t.(Integer); return ok && i == c }
func (i Integer) String() string {
	return fmt.Sprintf("%d", i)
}

type String uint64

func (String) Type() TermType      { return TermTypeString }
func (s String) Equal(t Term) bool { c, ok := t.(String); return ok && s == c }
func (s String) String() string {
	return fmt.Sprintf("#%d", s)
}

type Date uint64

func (Date) Type() TermType      { return TermTypeDate }
func (d Date) Equal(t Term) bool { c, ok := t.(Date); return ok && d == c }
func (d Date) String() string {
	return time.Unix(int64(d), 0).UTC().Format(time.RFC3339)
}

type Bytes []byte

func (Bytes) Type() TermType      { return TermTypeBytes }
func (b Bytes) Equal(t Term) bool { c, ok := t.(Bytes); return ok && bytes.Equal(b, c) }
func (b Bytes) String() string {
	return fmt.Sprintf("hex:%s", hex.EncodeToString(b))
}

type Bool bool

func (Bool) Type() TermType      { return TermTypeBool }
func (b Bool) Equal(t Term) bool { c, ok := t.(Bool); return ok && b == c }
func (b Bool) String() string {
	return fmt.Sprintf("%t", b)
}

// Null is the absence of a value (datalog v3.3). It equals only itself;
// `==` with another type is false, `===` is a type error.
type Null struct{}

func (Null) Type() TermType    { return TermTypeNull }
func (Null) Equal(t Term) bool { _, ok := t.(Null); return ok }
func (Null) String() string    { return "null" }

type Predicate struct {
	Name  String
	Terms []Term
}

func (p Predicate) Equal(p2 Predicate) bool {
	if p.Name != p2.Name || len(p.Terms) != len(p2.Terms) {
		return false
	}
	for i, id := range p.Terms {
		if !id.Equal(p2.Terms[i]) {
			return false
		}
	}

	return true
}

func (p Predicate) Match(p2 Predicate) bool {
	if p.Name != p2.Name || len(p.Terms) != len(p2.Terms) {
		return false
	}
	for i, id := range p.Terms {
		_, v1 := id.(Variable)
		_, v2 := p2.Terms[i].(Variable)
		if v1 || v2 {
			continue
		}
		if !id.Equal(p2.Terms[i]) {
			return false
		}
	}
	return true
}

func (p Predicate) Clone() Predicate {
	res := Predicate{Name: p.Name, Terms: make([]Term, len(p.Terms))}
	copy(res.Terms, p.Terms)
	return res
}

type Fact struct {
	Predicate
}

type Rule struct {
	Head        Predicate
	Body        []Predicate
	Expressions []Expression
	// Scopes is the `trusting` clause; empty means the scopes of the block.
	Scopes []Scope
}

type InvalidRuleError struct {
	Rule            Rule
	MissingVariable Variable
}

func (e InvalidRuleError) Error() string {
	return fmt.Sprintf("datalog: variable %d in head is missing from body and/or constraints", e.MissingVariable)
}

// variables lists the variables of the body, unbound.
func (r Rule) variables() MatchedVariables {
	variables := make(MatchedVariables)
	for _, predicate := range r.Body {
		for _, term := range predicate.Terms {
			if v, ok := term.(Variable); ok {
				variables[v] = nil
			}
		}
	}
	return variables
}

// apply derives the facts of the rule and calls emit for each, with its
// origin: the origins of the matched facts plus blockID, the block the rule
// belongs to. candidates holds, for each predicate of the body, the facts it
// may match. emit returns false to stop at that fact. A nil budget disables
// the limits.
func (r Rule) apply(blockID BlockID, candidates [][]factWithOrigin, syms *SymbolTable, externs ExternFuncs, budget *runBudget, emit func(Origin, Fact) (bool, error)) error {
	return match(r.variables(), r.Body, candidates, budget, func(m *matcher) (bool, error) {
		if err := budget.tick(tupleCost); err != nil {
			return false, err
		}
		for _, e := range r.Expressions {
			res, err := e.evaluate(m.vars, syms, externs, budget)
			if err != nil {
				return false, err
			}
			if !res.Equal(Bool(true)) {
				return true, nil
			}
		}

		predicate := r.Head.Clone()
		for i, term := range predicate.Terms {
			k, ok := term.(Variable)
			if !ok {
				continue
			}
			v, ok := m.vars[k]
			if !ok {
				return false, InvalidRuleError{r, k}
			}

			predicate.Terms[i] = *v
		}
		return emit(m.origin().With(blockID), Fact{predicate})
	})
}

// CheckKind selects how the queries of a Check are evaluated.
type CheckKind byte

const (
	// CheckKindOne passes when one query has at least one match.
	CheckKindOne CheckKind = iota
	// CheckKindAll passes when one query has at least one match and every
	// match of that query satisfies its expressions.
	CheckKindAll
	// CheckKindReject (`reject if`) passes when no query has a match.
	CheckKindReject
)

type Check struct {
	Queries []Rule
	Kind    CheckKind
}

type FactSet []Fact

func (s *FactSet) Insert(f Fact) bool {
	for _, v := range *s {
		if v.Equal(f.Predicate) {
			return false
		}
	}
	*s = append(*s, f)
	return true
}

func (s *FactSet) InsertAll(facts []Fact) {
	for _, f := range facts {
		s.Insert(f)
	}
}

func (s *FactSet) Equal(x *FactSet) bool {
	if len(*s) != len(*x) {
		return false
	}
	for _, f1 := range *x {
		found := false
		for _, f2 := range *s {
			if f1.Equal(f2.Predicate) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type runLimits struct {
	maxFacts      int
	maxIterations int
	maxDuration   time.Duration
	maxSteps      int
}

var defaultRunLimits = runLimits{
	maxFacts:      1000,
	maxIterations: 100,
	maxDuration:   2 * time.Millisecond,
	maxSteps:      1000,
}

// runBudget bounds an evaluation of a world. Steps are the deterministic
// unit of the specification: the world counts them over its whole life,
// across Run and the queries, against its step limit. Run is bounded in time
// as well: the loops on its path report work through tick, and the clock is
// read once per budgetCheckEvery units. A nil budget has no limit.
type runBudget struct {
	// steps is the counter of the world.
	steps    *int
	maxSteps int
	// now is nil for an evaluation without a time limit.
	now      func() time.Time
	deadline time.Time
	left     int
}

const (
	// in units of one Match or Equal call; a clock read costs about 10 units
	budgetCheckEvery = 1024
	// a binding of every predicate (expressions, derived fact) costs about this many units
	tupleCost = 32
)

// step records one step of the specification: a candidate fact tried for a
// predicate, an operator applied or a closure applied.
func (b *runBudget) step() error {
	if b == nil {
		return nil
	}
	*b.steps++
	if *b.steps > b.maxSteps {
		return ErrWorldRunLimitMaxSteps
	}
	return b.tick(1)
}

// tick reports work to the time limit.
func (b *runBudget) tick(work int) error {
	if b == nil || b.now == nil {
		return nil
	}
	if b.left -= work; b.left > 0 {
		return nil
	}
	b.left = budgetCheckEvery
	if b.now().After(b.deadline) {
		return ErrWorldRunLimitTimeout
	}
	return nil
}

var (
	ErrWorldRunLimitMaxFacts      = errors.New("datalog: world runtime limit: too many facts")
	ErrWorldRunLimitMaxIterations = errors.New("datalog: world runtime limit: too many iterations")
	ErrWorldRunLimitTimeout       = errors.New("datalog: world runtime limit: timeout")
	ErrWorldRunLimitMaxSteps      = errors.New("datalog: world runtime limit: too many steps")
)

type WorldOption func(w *World)

// WithExternFuncs registers the functions that extern::name calls resolve to.
func WithExternFuncs(externs ExternFuncs) WorldOption {
	return func(w *World) {
		w.externs = externs
	}
}

func WithMaxFacts(maxFacts int) WorldOption {
	return func(w *World) {
		w.runLimits.maxFacts = maxFacts
	}
}

func WithMaxIterations(maxIterations int) WorldOption {
	return func(w *World) {
		w.runLimits.maxIterations = maxIterations
	}
}

func WithMaxDuration(maxDuration time.Duration) WorldOption {
	return func(w *World) {
		w.runLimits.maxDuration = maxDuration
	}
}

// WithMaxSteps sets the step limit of the world: the most steps that Run and
// the queries may take in total over the life of the world, counted as the
// specification describes. An evaluation that goes over it stops with
// ErrWorldRunLimitMaxSteps.
func WithMaxSteps(maxSteps int) WorldOption {
	return func(w *World) {
		w.runLimits.maxSteps = maxSteps
	}
}

type factWithOrigin struct {
	origin Origin
	fact   Fact
}

// originFacts is the set of facts sharing one origin.
type originFacts struct {
	origin Origin
	facts  FactSet
}

type scopedRule struct {
	blockID BlockID
	trusted TrustedOrigins
	rule    Rule
}

// World holds the facts and rules of an authorization, each fact with the
// origin it derives from and each rule with the origins it trusts.
type World struct {
	// facts is kept sorted by origin so that iteration is deterministic.
	facts []originFacts
	rules []scopedRule

	runLimits runLimits
	externs   ExternFuncs
	// steps counts the steps taken by Run and the queries since the world
	// was created.
	steps int
	// clock is read by the run limits; nil means time.Now and tests inject a fake one
	clock func() time.Time
}

func NewWorld(opts ...WorldOption) *World {
	w := &World{
		runLimits: defaultRunLimits,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// AddFact adds a fact stated by the blocks of origin. Returns false when the
// world already had it under that origin.
func (w *World) AddFact(origin Origin, f Fact) bool {
	return w.factsOf(origin).Insert(f)
}

// factsOf returns the facts of origin, adding the origin when the world has
// none. The pointer is valid until the next origin is added.
func (w *World) factsOf(origin Origin) *FactSet {
	i, found := slices.BinarySearchFunc(w.facts, origin, func(of originFacts, o Origin) int {
		return of.origin.Compare(o)
	})
	if !found {
		w.facts = slices.Insert(w.facts, i, originFacts{origin: origin.With()})
	}
	return &w.facts[i].facts
}

// Facts returns the facts of the world grouped by origin, in origin order.
func (w *World) Facts() []OriginFacts {
	res := make([]OriginFacts, 0, len(w.facts))
	for _, of := range w.facts {
		if len(of.facts) == 0 {
			continue
		}
		facts := make(FactSet, len(of.facts))
		copy(facts, of.facts)
		res = append(res, OriginFacts{Origin: of.origin.With(), Facts: facts})
	}
	return res
}

// OriginFacts is a group of facts sharing an origin.
type OriginFacts struct {
	Origin Origin
	Facts  FactSet
}

func (w *World) factCount() int {
	n := 0
	for _, of := range w.facts {
		n += len(of.facts)
	}
	return n
}

// visibleFacts flattens the facts whose origin is trusted.
func (w *World) visibleFacts(trusted TrustedOrigins) []factWithOrigin {
	var res []factWithOrigin
	for _, of := range w.facts {
		if !trusted.Contains(of.origin) {
			continue
		}
		for _, f := range of.facts {
			res = append(res, factWithOrigin{origin: of.origin, fact: f})
		}
	}
	return res
}

// candidates lists, for each predicate of a rule body, the facts it may
// match: those of a trusted origin with the name and the number of terms of
// the predicate.
func (w *World) candidates(trusted TrustedOrigins, body []Predicate) [][]factWithOrigin {
	res := make([][]factWithOrigin, len(body))
	for _, of := range w.facts {
		if !trusted.Contains(of.origin) {
			continue
		}
		for _, f := range of.facts {
			for i, p := range body {
				if f.Name == p.Name && len(f.Terms) == len(p.Terms) {
					res[i] = append(res[i], factWithOrigin{origin: of.origin, fact: f})
				}
			}
		}
	}
	return res
}

// budget returns the limits of an evaluation of the world: the steps the
// world has left and, for a timed evaluation, a deadline of its own.
func (w *World) budget(timed bool) *runBudget {
	b := &runBudget{steps: &w.steps, maxSteps: w.runLimits.maxSteps}
	if timed {
		b.now = w.now
		b.deadline = w.now().Add(w.runLimits.maxDuration)
		b.left = budgetCheckEvery
	}
	return b
}

// AddRule adds a rule from block blockID, reading the facts of the trusted
// origins.
func (w *World) AddRule(blockID BlockID, trusted TrustedOrigins, r Rule) {
	w.rules = append(w.rules, scopedRule{blockID: blockID, trusted: trusted.With(), rule: r})
}

func (w *World) ResetRules() {
	w.rules = nil
}

// BlockRule is a rule with the block it belongs to.
type BlockRule struct {
	BlockID BlockID
	Rule    Rule
}

// Rules returns the rules of the world with their block, in insertion order.
func (w *World) Rules() []BlockRule {
	res := make([]BlockRule, len(w.rules))
	for i, sr := range w.rules {
		res[i] = BlockRule{BlockID: sr.blockID, Rule: sr.rule}
	}
	return res
}

func (w *World) now() time.Time {
	if w.clock == nil {
		return time.Now()
	}
	return w.clock()
}

// Run applies the rules until no new fact appears or a limit is reached.
func (w *World) Run(syms *SymbolTable) error {
	budget := w.budget(true)
	deadline := budget.deadline
	for i := 0; i < w.runLimits.maxIterations; i++ {
		// Checked here as well so the limit applies to a world without rules.
		if w.now().After(deadline) {
			return ErrWorldRunLimitTimeout
		}
		var newFacts []factWithOrigin
		for _, sr := range w.rules {
			if w.now().After(deadline) {
				return ErrWorldRunLimitTimeout
			}
			candidates := w.candidates(sr.trusted, sr.rule.Body)
			err := sr.rule.apply(sr.blockID, candidates, syms, w.externs, budget, func(origin Origin, f Fact) (bool, error) {
				newFacts = append(newFacts, factWithOrigin{origin, f})
				return true, nil
			})
			if err != nil {
				return err
			}
		}

		// The merge only appends to the facts of an origin or adds an origin,
		// so the slice headers saved here still describe the previous
		// iteration: restoring them on a timeout rolls the merge back, and the
		// world never holds part of an iteration.
		prevFacts := slices.Clone(w.facts)
		prevCount := w.factCount()
		for _, nf := range newFacts {
			facts := w.factsOf(nf.origin)
			// Insert scans the facts of the origin
			if err := budget.tick(len(*facts) + 1); err != nil {
				w.facts = prevFacts
				return err
			}
			facts.Insert(nf.fact)
		}

		newCount := w.factCount()
		if newCount >= w.runLimits.maxFacts {
			return ErrWorldRunLimitMaxFacts
		}

		// last iteration did not generate any new facts, so we can stop here
		if newCount == prevCount {
			return nil
		}
	}
	return ErrWorldRunLimitMaxIterations
}

// Query returns the facts of the trusted origins matching the predicate,
// where a variable matches any term.
func (w *World) Query(trusted TrustedOrigins, pred Predicate) *FactSet {
	res := &FactSet{}
	for _, fo := range w.visibleFacts(trusted) {
		f := fo.fact
		if f.Name != pred.Name || len(f.Terms) != len(pred.Terms) {
			continue
		}

		matches := true
		for i := 0; i < len(pred.Terms); i++ {
			if pID := pred.Terms[i]; pID.Type() != TermTypeVariable && !f.Terms[i].Equal(pID) {
				matches = false
				break
			}
		}

		if matches {
			res.Insert(f)
		}
	}
	return res
}

// QueryRule returns the facts the rule, from block blockID, derives from the
// facts of the trusted origins. An error from an expression (overflow,
// division by zero, type mismatch) is returned rather than treated as a
// non-match.
func (w *World) QueryRule(rule Rule, blockID BlockID, trusted TrustedOrigins, syms *SymbolTable) (*FactSet, error) {
	newFacts := &FactSet{}
	err := rule.apply(blockID, w.candidates(trusted, rule.Body), syms, w.externs, w.budget(false), func(_ Origin, f Fact) (bool, error) {
		newFacts.Insert(f)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return newFacts, nil
}

// QueryMatch reports whether the rule, from block blockID, derives a fact
// from the facts of the trusted origins. Unlike QueryRule it stops at the
// first one, which is all a check or a policy needs.
func (w *World) QueryMatch(rule Rule, blockID BlockID, trusted TrustedOrigins, syms *SymbolTable) (bool, error) {
	found := false
	err := rule.apply(blockID, w.candidates(trusted, rule.Body), syms, w.externs, w.budget(false), func(Origin, Fact) (bool, error) {
		found = true
		return false, nil
	})
	if err != nil {
		return false, err
	}
	return found, nil
}

// QueryMatchAll reports whether the body of the rule matches at least once
// in the facts of the trusted origins and its expressions hold for every
// match (the semantics of `check all`). It stops at the first match whose
// expressions do not hold.
func (w *World) QueryMatchAll(rule Rule, trusted TrustedOrigins, syms *SymbolTable) (bool, error) {
	budget := w.budget(false)
	matched, holds := false, true
	err := match(rule.variables(), rule.Body, w.candidates(trusted, rule.Body), budget, func(m *matcher) (bool, error) {
		matched = true
		for _, e := range rule.Expressions {
			v, err := e.evaluate(m.vars, syms, w.externs, budget)
			if err != nil {
				return false, err
			}
			if !v.Equal(Bool(true)) {
				holds = false
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return false, err
	}
	return matched && holds, nil
}

// Clone copies the facts, the rules and the limits of the world. The copy
// starts with its own step count, at zero.
func (w *World) Clone() *World {
	facts := make([]originFacts, len(w.facts))
	for i, of := range w.facts {
		facts[i] = originFacts{origin: of.origin.With(), facts: slices.Clone(of.facts)}
	}
	return &World{
		facts:     facts,
		rules:     slices.Clone(w.rules),
		runLimits: w.runLimits,
		externs:   w.externs,
		clock:     w.clock,
	}
}

type MatchedVariables map[Variable]*Term

func (m MatchedVariables) Insert(k Variable, v Term) bool {
	existing := m[k]
	if existing == nil {
		m[k] = &v
		return true
	}
	return v.Equal(*existing)
}

func (m MatchedVariables) Complete() map[Variable]*Term {
	for _, v := range m {
		if v == nil {
			return nil
		}
	}
	return (map[Variable]*Term)(m)
}

func (m MatchedVariables) Clone() MatchedVariables {
	res := make(MatchedVariables, len(m))
	maps.Copy(res, m)
	return res
}

// matcher enumerates the bindings of the variables of a rule body for which
// every predicate matches a fact. It follows the evaluation the specification
// counts steps on: the predicates are matched in order, each against its
// candidates, with the variables the previous predicates bound, and every
// candidate tried is one step.
type matcher struct {
	body       []Predicate
	candidates [][]factWithOrigin
	// vars holds the variables of the body, bound up to the predicate
	// being matched.
	vars MatchedVariables
	// bound and origins hold, for each predicate, the variables its
	// current candidate bound and the origin of that candidate.
	bound   [][]Variable
	origins []Origin
	budget  *runBudget
	yield   func(*matcher) (bool, error)
}

// match calls yield for each binding of variables, until yield returns false
// or an error. candidates holds the facts each predicate of body may match.
// The matcher passed to yield has the binding in vars, valid during the call
// only, and the origin of the facts it comes from.
func match(variables MatchedVariables, body []Predicate, candidates [][]factWithOrigin, budget *runBudget, yield func(*matcher) (bool, error)) error {
	m := &matcher{
		body:       body,
		candidates: candidates,
		vars:       variables,
		bound:      make([][]Variable, len(body)),
		origins:    make([]Origin, len(body)),
		budget:     budget,
		yield:      yield,
	}
	_, err := m.from(0)
	return err
}

// from matches the predicates from depth on. It reports whether the
// enumeration goes on with the next candidate of the predicates before.
func (m *matcher) from(depth int) (bool, error) {
	if depth == len(m.body) {
		return m.yield(m)
	}
	pred := m.body[depth]
	for _, c := range m.candidates[depth] {
		if err := m.budget.step(); err != nil {
			return false, err
		}
		if !c.fact.Match(pred) || !m.bind(depth, pred, c.fact) {
			continue
		}
		m.origins[depth] = c.origin
		more, err := m.from(depth + 1)
		m.unbind(depth)
		if err != nil || !more {
			return false, err
		}
	}
	return true, nil
}

// bind binds the variables of the predicate to the terms of the fact. When a
// variable is already bound to another term it reports false and leaves the
// variables as they were.
func (m *matcher) bind(depth int, pred Predicate, fact Fact) bool {
	for i, term := range pred.Terms {
		v, ok := term.(Variable)
		if !ok {
			continue
		}
		if bound := m.vars[v]; bound != nil {
			if !(*bound).Equal(fact.Terms[i]) {
				m.unbind(depth)
				return false
			}
			continue
		}
		value := fact.Terms[i]
		m.vars[v] = &value
		m.bound[depth] = append(m.bound[depth], v)
	}
	return true
}

func (m *matcher) unbind(depth int) {
	for _, v := range m.bound[depth] {
		m.vars[v] = nil
	}
	m.bound[depth] = m.bound[depth][:0]
}

// origin is the origin of the current binding: the blocks of every fact it
// was built from.
func (m *matcher) origin() Origin {
	var res Origin
	for _, o := range m.origins {
		res = append(res, o...)
	}
	slices.Sort(res)
	return slices.Compact(res)
}
