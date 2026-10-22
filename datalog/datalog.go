// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"bytes"
	"encoding/binary"
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
	sort.Strings(eltStr)
	return fmt.Sprintf("[%s]", strings.Join(eltStr, ", "))
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
}

type InvalidRuleError struct {
	Rule            Rule
	MissingVariable Variable
}

func (e InvalidRuleError) Error() string {
	return fmt.Sprintf("datalog: variable %d in head is missing from body and/or constraints", e.MissingVariable)
}

func (r Rule) Apply(facts *FactSet, newFacts *FactSet, syms *SymbolTable) error {
	return r.apply(facts, indexFacts(newFacts), syms, nil)
}

// apply returns ErrWorldRunLimitTimeout once the budget's deadline passes. A nil budget disables the limit.
func (r Rule) apply(facts *FactSet, newFacts *indexedFacts, syms *SymbolTable, budget *runBudget) error {
	// extract all variables from the rule body
	variables := make(MatchedVariables)
	for _, predicate := range r.Body {
		for _, term := range predicate.Terms {
			v, ok := term.(Variable)
			if !ok {
				continue
			}
			variables[v] = nil
		}
	}

	combinations, err := combine(variables, r.Body, r.Expressions, facts, syms, budget)
	if err != nil {
		return err
	}

	for _, res := range combinations {
		predicate := r.Head.Clone()
		for i, term := range predicate.Terms {
			k, ok := term.(Variable)
			if !ok {
				continue
			}
			v, ok := res[k]
			if !ok {
				return InvalidRuleError{r, k}
			}

			predicate.Terms[i] = *v
		}
		if err := budget.tick(tupleCost); err != nil {
			return err
		}
		newFacts.insert(Fact{predicate})
	}

	return nil
}

type Check struct {
	Queries []Rule
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

// factKey appends a canonical encoding of a predicate to buf: two predicates
// have the same key if and only if Predicate.Equal holds, so it can stand in
// for Equal in a map.
func factKey(buf []byte, p Predicate) []byte {
	buf = binary.BigEndian.AppendUint64(buf, uint64(p.Name))
	buf = binary.BigEndian.AppendUint64(buf, uint64(len(p.Terms)))
	for _, t := range p.Terms {
		buf = appendTermKey(buf, t)
	}
	return buf
}

func appendTermKey(buf []byte, t Term) []byte {
	switch v := t.(type) {
	case Variable:
		return binary.BigEndian.AppendUint32(append(buf, 'v'), uint32(v))
	case Integer:
		return binary.BigEndian.AppendUint64(append(buf, 'i'), uint64(v))
	case String:
		return binary.BigEndian.AppendUint64(append(buf, 's'), uint64(v))
	case Date:
		return binary.BigEndian.AppendUint64(append(buf, 'd'), uint64(v))
	case Bool:
		if v {
			return append(buf, 'B', 1)
		}
		return append(buf, 'B', 0)
	case Bytes:
		buf = binary.BigEndian.AppendUint64(append(buf, 'b'), uint64(len(v)))
		return append(buf, v...)
	case Set:
		// Set.Equal compares lengths, then membership regardless of order or
		// repetition, so the key is the length plus the sorted distinct elements.
		elems := make([]string, 0, len(v))
		for _, e := range v {
			elems = append(elems, string(appendTermKey(nil, e)))
		}
		slices.Sort(elems)
		elems = slices.Compact(elems)
		buf = binary.BigEndian.AppendUint64(append(buf, 'S'), uint64(len(v)))
		buf = binary.BigEndian.AppendUint64(buf, uint64(len(elems)))
		for _, e := range elems {
			buf = binary.BigEndian.AppendUint64(buf, uint64(len(e)))
			buf = append(buf, e...)
		}
		return buf
	default:
		// unknown Term implementations fall back to their textual form
		s := t.String()
		buf = binary.BigEndian.AppendUint64(append(buf, 'X'), uint64(len(s)))
		return append(buf, s...)
	}
}

// indexedFacts is a FactSet that switches from a linear duplicate scan to a
// key index once it holds indexThreshold facts, where hashing a fact becomes
// cheaper than comparing it against every fact already in the set.
type indexedFacts struct {
	set     *FactSet
	index   map[string]struct{}
	scratch []byte
}

const indexThreshold = 32

func indexFacts(set *FactSet) *indexedFacts {
	s := &indexedFacts{set: set}
	if len(*set) >= indexThreshold {
		s.buildIndex()
	}
	return s
}

func (s *indexedFacts) buildIndex() {
	s.index = make(map[string]struct{}, 2*len(*s.set))
	for _, f := range *s.set {
		s.scratch = factKey(s.scratch[:0], f.Predicate)
		s.index[string(s.scratch)] = struct{}{}
	}
}

func (s *indexedFacts) insert(f Fact) bool {
	if s.index == nil {
		if len(*s.set) < indexThreshold {
			return s.set.Insert(f)
		}
		s.buildIndex()
	}
	s.scratch = factKey(s.scratch[:0], f.Predicate)
	if _, dup := s.index[string(s.scratch)]; dup {
		return false
	}
	s.index[string(s.scratch)] = struct{}{}
	*s.set = append(*s.set, f)
	return true
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
}

var defaultRunLimits = runLimits{
	maxFacts:      1000,
	maxIterations: 100,
	maxDuration:   2 * time.Millisecond,
}

// runBudget is the interpreter's cooperative cancellation point: every unbounded
// loop reports its work through tick, which polls the clock once per
// budgetCheckEvery units so the per-step cost stays negligible.
type runBudget struct {
	deadline time.Time
	left     int
}

const (
	budgetCheckEvery = 1024
	// a full binding (map clone + expressions) costs about this many Match attempts
	tupleCost = 32
)

func newRunBudget(deadline time.Time) *runBudget {
	return &runBudget{deadline: deadline, left: budgetCheckEvery}
}

// tick is a no-op on a nil budget so unlimited callers pay only the nil check.
func (b *runBudget) tick(work int) error {
	if b == nil {
		return nil
	}
	if b.left -= work; b.left > 0 {
		return nil
	}
	b.left = budgetCheckEvery
	if time.Now().After(b.deadline) {
		return ErrWorldRunLimitTimeout
	}
	return nil
}

var (
	ErrWorldRunLimitMaxFacts      = errors.New("datalog: world runtime limit: too many facts")
	ErrWorldRunLimitMaxIterations = errors.New("datalog: world runtime limit: too many iterations")
	ErrWorldRunLimitTimeout       = errors.New("datalog: world runtime limit: timeout")
)

type WorldOption func(w *World)

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

type World struct {
	facts *FactSet
	// idx wraps facts; nil after Clone and rebuilt by indexed()
	idx   *indexedFacts
	rules []Rule

	runLimits runLimits
}

func NewWorld(opts ...WorldOption) *World {
	w := &World{
		facts:     &FactSet{},
		runLimits: defaultRunLimits,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

func (w *World) AddFact(f Fact) {
	w.indexed().insert(f)
}

// indexed returns w.facts with its duplicate index, rebuilding it when it no
// longer covers the set (after Clone, or a write through Facts()).
func (w *World) indexed() *indexedFacts {
	if w.idx == nil || (w.idx.index != nil && len(w.idx.index) != len(*w.facts)) {
		w.idx = indexFacts(w.facts)
	}
	return w.idx
}

func (w *World) Facts() *FactSet {
	return w.facts
}

func (w *World) AddRule(r Rule) {
	w.rules = append(w.rules, r)
}

func (w *World) ResetRules() {
	w.rules = make([]Rule, 0)
}

func (w *World) Rules() []Rule {
	return w.rules
}

func (w *World) Run(syms *SymbolTable) error {
	deadline := time.Now().Add(w.runLimits.maxDuration)
	budget := newRunBudget(deadline)
	for i := 0; i < w.runLimits.maxIterations; i++ {
		// Checked here as well so the limit applies to a world without rules.
		if time.Now().After(deadline) {
			return ErrWorldRunLimitTimeout
		}
		newFacts := &indexedFacts{set: &FactSet{}}
		for _, r := range w.rules {
			if time.Now().After(deadline) {
				return ErrWorldRunLimitTimeout
			}
			if err := r.apply(w.facts, newFacts, syms, budget); err != nil {
				return err
			}
		}

		prevCount := len(*w.facts)
		merged := w.indexed()
		for _, f := range *newFacts.set {
			if err := budget.tick(tupleCost); err != nil {
				return err
			}
			merged.insert(f)
		}

		newCount := len(*w.facts)
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

func (w *World) Query(pred Predicate) *FactSet {
	res := &FactSet{}
	for _, f := range *w.facts {
		if f.Name != pred.Name {
			continue
		}

		// if the predicate has a different number of IDs
		// the fact must not match
		if len(f.Terms) != len(pred.Terms) {
			continue
		}

		matches := true
		for i := 0; i < len(pred.Terms); i++ {
			fID := f.Terms[i]
			pID := pred.Terms[i]

			if pID.Type() != TermTypeVariable && !fID.Equal(pID) {
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

func (w *World) QueryRule(rule Rule, syms *SymbolTable) *FactSet {
	newFacts := &FactSet{}
	// swallowing the error explicitly since propagating it would break the current API
	_ = rule.Apply(w.facts, newFacts, syms)
	return newFacts
}

func (w *World) Clone() *World {
	newFacts := new(FactSet)
	*newFacts = *w.facts
	return &World{
		facts:     newFacts,
		rules:     append([]Rule{}, w.rules...),
		runLimits: w.runLimits,
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

// combine enumerates every binding of the body predicates that is consistent
// with the facts and satisfies the expressions, in lexicographic order of fact
// indexes. Bindings are propagated level by level so a conflicting tuple is
// pruned at the first predicate that reveals it, like biscuit-rust's CombineIt.
func combine(
	variables MatchedVariables,
	predicates []Predicate,
	expressions []Expression,
	facts *FactSet,
	syms *SymbolTable,
	budget *runBudget,
) ([]MatchedVariables, error) {
	c := &combiner{
		vars:        variables,
		cells:       make(map[Variable]*Term, len(variables)),
		predicates:  predicates,
		expressions: expressions,
		facts:       facts,
		syms:        syms,
		budget:      budget,
	}
	for v := range variables {
		c.cells[v] = new(Term)
	}
	if err := c.search(0); err != nil {
		return nil, err
	}
	return c.res, nil
}

type combiner struct {
	vars MatchedVariables
	// cells holds one stable storage slot per variable, so binding does not allocate
	cells       map[Variable]*Term
	predicates  []Predicate
	expressions []Expression
	facts       *FactSet
	syms        *SymbolTable
	budget      *runBudget

	// trail records the variables bound so far, so a level can be undone on backtrack
	trail []Variable
	res   []MatchedVariables
}

func (c *combiner) search(level int) error {
	if level == len(c.predicates) {
		return c.emit()
	}
	pred := c.predicates[level]
	// one tick per scan keeps the check out of the inner loop; a scan is at most |facts| steps
	if err := c.budget.tick(len(*c.facts)); err != nil {
		return err
	}
	for i := range *c.facts {
		fact := (*c.facts)[i]
		if !fact.Match(pred) {
			continue
		}
		mark := len(c.trail)
		if c.bind(pred, fact) {
			if err := c.search(level + 1); err != nil {
				return err
			}
		}
		c.unbind(mark)
	}
	return nil
}

func (c *combiner) bind(pred Predicate, fact Fact) bool {
	for j, term := range pred.Terms {
		v, ok := term.(Variable)
		if !ok {
			continue
		}
		if existing := c.vars[v]; existing != nil {
			if !fact.Terms[j].Equal(*existing) {
				return false
			}
			continue
		}
		cell := c.cells[v]
		*cell = fact.Terms[j]
		c.vars[v] = cell
		c.trail = append(c.trail, v)
	}
	return true
}

func (c *combiner) unbind(mark int) {
	for _, v := range c.trail[mark:] {
		c.vars[v] = nil
	}
	c.trail = c.trail[:mark]
}

func (c *combiner) emit() error {
	if err := c.budget.tick(tupleCost); err != nil {
		return err
	}
	complete := c.vars.Complete()
	if complete == nil {
		return nil
	}
	for _, e := range c.expressions {
		r, err := e.Evaluate(complete, c.syms)
		if err != nil {
			return err
		}
		if !r.Equal(Bool(true)) {
			return nil
		}
	}
	// the cells are reused by later tuples, so the result needs its own copies
	snapshot := make(MatchedVariables, len(c.vars))
	for v, t := range c.vars {
		val := *t
		snapshot[v] = &val
	}
	c.res = append(c.res, snapshot)
	return nil
}
