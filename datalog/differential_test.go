// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// naiveApply is the reference for Rule.apply: it enumerates the full cross
// product of the facts over the body predicates and keeps the tuples whose
// bindings are consistent and whose expressions hold. It shares nothing with
// the interpreter's join, so the two can only agree by computing the same
// relation.
func naiveApply(r Rule, facts FactSet, syms *SymbolTable) (FactSet, error) {
	var out FactSet
	idx := make([]int, len(r.Body))
	for {
		bindings := make(map[Variable]Term)
		consistent := true
		for level, pred := range r.Body {
			f := facts[idx[level]]
			if f.Name != pred.Name || len(f.Terms) != len(pred.Terms) {
				consistent = false
				break
			}
			for j, term := range pred.Terms {
				v, isVar := term.(Variable)
				if !isVar {
					if !term.Equal(f.Terms[j]) {
						consistent = false
					}
				} else if bound, ok := bindings[v]; ok {
					if !bound.Equal(f.Terms[j]) {
						consistent = false
					}
				} else {
					bindings[v] = f.Terms[j]
				}
				if !consistent {
					break
				}
			}
			if !consistent {
				break
			}
		}

		if consistent {
			values := make(map[Variable]*Term, len(bindings))
			for v, t := range bindings {
				values[v] = &t
			}
			hold := true
			for _, e := range r.Expressions {
				res, err := e.Evaluate(values, syms)
				if err != nil {
					return nil, err
				}
				if !res.Equal(Bool(true)) {
					hold = false
					break
				}
			}
			if hold {
				head := r.Head.Clone()
				for i, term := range head.Terms {
					v, ok := term.(Variable)
					if !ok {
						continue
					}
					bound, ok := bindings[v]
					if !ok {
						return nil, InvalidRuleError{r, v}
					}
					head.Terms[i] = bound
				}
				out.Insert(Fact{head})
			}
		}

		// advance the odometer; an empty body evaluates exactly once
		level := len(idx) - 1
		for level >= 0 {
			idx[level]++
			if idx[level] < len(facts) {
				break
			}
			idx[level] = 0
			level--
		}
		if level < 0 {
			return out, nil
		}
	}
}

// naiveRun applies every rule to the current facts until no new fact appears.
func naiveRun(facts FactSet, rules []Rule, syms *SymbolTable) (FactSet, error) {
	for {
		before := len(facts)
		var derived FactSet
		for _, r := range rules {
			out, err := naiveApply(r, facts, syms)
			if err != nil {
				return nil, err
			}
			derived.InsertAll(out)
		}
		facts.InsertAll(derived)
		if len(facts) == before {
			return facts, nil
		}
	}
}

// program generation

type termKind int

const (
	kindInt termKind = iota
	kindString
	kindBool
	kindSet
	kindCount
)

// genPredicate fixes a name, an arity and the kind of every position, so the
// generated facts of a predicate share a shape and joins have a chance to match.
type genPredicate struct {
	name  String
	kinds []termKind
}

type generator struct {
	rng   *rand.Rand
	preds []genPredicate
}

// a small vocabulary keeps the domains dense enough that joins, duplicates
// and set equality quirks all show up in short programs
const (
	genIntDomain    = 4
	genStringDomain = 3
	genVariables    = 4
	genMaxArity     = 3
	genMaxBody      = 3
	genMaxFacts     = 48
	genMaxRules     = 4
)

func newGenerator(seed uint64) *generator {
	g := &generator{rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
	n := 2 + g.rng.IntN(3)
	for i := range n {
		arity := 1 + g.rng.IntN(genMaxArity)
		kinds := make([]termKind, arity)
		for j := range kinds {
			kinds[j] = termKind(g.rng.IntN(int(kindCount)))
		}
		g.preds = append(g.preds, genPredicate{name: String(100 + i), kinds: kinds})
	}
	return g
}

func (g *generator) constant(kind termKind) Term {
	switch kind {
	case kindInt:
		return Integer(g.rng.IntN(genIntDomain))
	case kindString:
		return String(200 + g.rng.IntN(genStringDomain))
	case kindBool:
		return Bool(g.rng.IntN(2) == 0)
	default:
		// repetition is allowed on purpose: Set.Equal is length-sensitive
		s := make(Set, g.rng.IntN(3))
		for i := range s {
			s[i] = Integer(g.rng.IntN(3))
		}
		return s
	}
}

func (g *generator) fact() Fact {
	p := g.preds[g.rng.IntN(len(g.preds))]
	terms := make([]Term, len(p.kinds))
	for i, k := range p.kinds {
		terms[i] = g.constant(k)
	}
	return Fact{Predicate{Name: p.name, Terms: terms}}
}

// rule builds a rule whose head variables are bound in the body, and records
// which kind each variable was first used with so expressions can be typed.
func (g *generator) rule() Rule {
	bodyLen := g.rng.IntN(genMaxBody + 1)
	body := make([]Predicate, 0, bodyLen)
	varKinds := make(map[Variable]termKind)
	for range bodyLen {
		p := g.preds[g.rng.IntN(len(g.preds))]
		terms := make([]Term, len(p.kinds))
		for i, k := range p.kinds {
			if g.rng.IntN(3) == 0 {
				terms[i] = g.constant(k)
				continue
			}
			v := Variable(g.rng.IntN(genVariables))
			terms[i] = v
			if _, seen := varKinds[v]; !seen {
				varKinds[v] = k
			}
		}
		body = append(body, Predicate{Name: p.name, Terms: terms})
	}

	bound := make([]Variable, 0, len(varKinds))
	for v := range varKinds {
		bound = append(bound, v)
	}
	// a stable order keeps the program a pure function of the seed
	for i := 1; i < len(bound); i++ {
		for j := i; j > 0 && bound[j] < bound[j-1]; j-- {
			bound[j], bound[j-1] = bound[j-1], bound[j]
		}
	}

	hp := g.preds[g.rng.IntN(len(g.preds))]
	head := Predicate{Name: hp.name, Terms: make([]Term, len(hp.kinds))}
	for i, k := range hp.kinds {
		if len(bound) > 0 && g.rng.IntN(2) == 0 {
			head.Terms[i] = bound[g.rng.IntN(len(bound))]
		} else {
			head.Terms[i] = g.constant(k)
		}
	}

	var exprs []Expression
	for range g.rng.IntN(3) {
		if e, ok := g.expression(bound, varKinds); ok {
			exprs = append(exprs, e)
		}
	}
	return Rule{Head: head, Body: body, Expressions: exprs}
}

func (g *generator) expression(bound []Variable, kinds map[Variable]termKind) (Expression, bool) {
	if len(bound) == 0 {
		return Expression{Value{Bool(g.rng.IntN(4) != 0)}}, true
	}
	v := bound[g.rng.IntN(len(bound))]
	switch g.rng.IntN(5) {
	case 0:
		return Expression{Value{v}, Value{g.constant(kinds[v])}, BinaryOp{Equal{}}}, true
	case 1:
		return Expression{Value{v}, Value{g.constant(kinds[v])}, BinaryOp{Equal{}}, UnaryOp{Negate{}}}, true
	case 2:
		w := bound[g.rng.IntN(len(bound))]
		return Expression{Value{v}, Value{w}, BinaryOp{Equal{}}}, true
	case 3:
		if kinds[v] != kindInt {
			return nil, false
		}
		return Expression{Value{v}, Value{Integer(g.rng.IntN(genIntDomain))}, BinaryOp{LessThan{}}}, true
	default:
		if kinds[v] == kindSet {
			return nil, false
		}
		set := Set{g.constant(kinds[v]), g.constant(kinds[v])}
		return Expression{Value{set}, Value{v}, BinaryOp{Contains{}}}, true
	}
}

func (g *generator) program() (FactSet, []Rule) {
	var facts FactSet
	for range 1 + g.rng.IntN(genMaxFacts) {
		facts.Insert(g.fact())
	}
	rules := make([]Rule, 1+g.rng.IntN(genMaxRules))
	for i := range rules {
		rules[i] = g.rule()
	}
	return facts, rules
}

// checkWorldMatchesNaive runs one generated program through the interpreter
// and the reference and requires the same fixpoint, then the same answer to
// every rule queried against that fixpoint.
func checkWorldMatchesNaive(t *testing.T, seed uint64) {
	g := newGenerator(seed)
	facts, rules := g.program()
	syms := &SymbolTable{}

	w := NewWorld(WithMaxFacts(1<<20), WithMaxIterations(1<<10), WithMaxDuration(time.Minute))
	for _, f := range facts {
		w.AddFact(f)
	}
	for _, r := range rules {
		w.AddRule(r)
	}
	err := w.Run(syms)

	want, wantErr := naiveRun(append(FactSet(nil), facts...), rules, syms)
	if wantErr != nil {
		require.Error(t, err, "seed %d: reference failed with %v", seed, wantErr)
		return
	}
	require.NoError(t, err, "seed %d", seed)
	requireSameFacts(t, seed, want, *w.Facts())

	for i, r := range rules {
		wantQ, err := naiveApply(r, *w.Facts(), syms)
		require.NoError(t, err)
		requireSameFacts(t, seed, wantQ, *w.QueryRule(r, syms), "rule %d", i)
	}
}

func requireSameFacts(t *testing.T, seed uint64, want, got FactSet, msgAndArgs ...any) {
	t.Helper()
	if want.Equal(&got) {
		return
	}
	d := SymbolDebugger{SymbolTable: &SymbolTable{}}
	require.Failf(t, "fact sets differ", "seed %d %v\nwant %s\ngot  %s", seed, msgAndArgs, d.FactSet(&want), d.FactSet(&got))
}

func TestWorldRunMatchesNaive(t *testing.T) {
	for seed := range uint64(2000) {
		checkWorldMatchesNaive(t, seed)
	}
}

func FuzzWorldRunMatchesNaive(f *testing.F) {
	for seed := range uint64(8) {
		f.Add(seed)
	}
	f.Fuzz(checkWorldMatchesNaive)
}
