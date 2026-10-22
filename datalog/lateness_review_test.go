//go:build review

// Manual harness: go test ./datalog -tags review -run TestReviewOvershoot -v
// Reports how far past WithMaxDuration Run returns for the three loop shapes
// (candidate scan, full-tuple evaluation, fact materialisation).

package datalog

import (
	"errors"
	"sort"
	"testing"
	"time"
)

// Temporary review helper: measures how far past maxDuration Run returns.
func measureOvershoot(t *testing.T, name string, build func() (*World, *SymbolTable), budget time.Duration, want ...error) {
	t.Helper()
	const runs = 15
	late := make([]time.Duration, 0, runs)
	for range runs {
		w, syms := build()
		start := time.Now()
		err := w.Run(syms)
		elapsed := time.Since(start)
		ok := false
		for _, e := range want {
			ok = ok || errors.Is(err, e)
		}
		if !ok {
			t.Fatalf("%s: Run() = %v, want one of %v (elapsed %v)", name, err, want, elapsed)
		}
		late = append(late, elapsed-budget)
	}
	sort.Slice(late, func(i, j int) bool { return late[i] < late[j] })
	t.Logf("%-28s budget=%v  overshoot p50=%v p90=%v max=%v", name, budget, late[runs/2], late[runs*9/10], late[runs-1])
}

func TestReviewOvershoot(t *testing.T) {
	const budget = 2 * time.Millisecond

	// Shape of the PR's own test: last predicate never matches, so every
	// level-3 scan ends in a mismatch and the work is dominated by descents.
	measureOvershoot(t, "last-pred-miss (PR test)", func() (*World, *SymbolTable) {
		syms := &SymbolTable{}
		q, none, p := syms.Insert("q"), syms.Insert("none"), syms.Insert("p")
		w := NewWorld(WithMaxDuration(budget))
		for i := range 200 {
			w.AddFact(Fact{Predicate{q, []Term{Integer(i)}}})
		}
		w.AddRule(Rule{
			Head: Predicate{p, []Term{Variable(0)}},
			Body: []Predicate{
				{q, []Term{Variable(0)}}, {q, []Term{Variable(1)}},
				{q, []Term{Variable(2)}}, {none, []Term{Variable(3)}},
			},
		})
		return w, syms
	}, budget, ErrWorldRunLimitTimeout)

	// Last predicate matches everything: each descent is followed by |facts|
	// full-tuple evaluations (map clone + expression) that are never counted.
	measureOvershoot(t, "last-pred-match-all", func() (*World, *SymbolTable) {
		syms := &SymbolTable{}
		q, p := syms.Insert("q"), syms.Insert("p")
		w := NewWorld(WithMaxDuration(budget), WithMaxFacts(1<<20))
		for i := range 1000 {
			w.AddFact(Fact{Predicate{q, []Term{Integer(i)}}})
		}
		w.AddRule(Rule{
			Head: Predicate{p, []Term{Variable(0)}},
			Body: []Predicate{{q, []Term{Variable(0)}}, {q, []Term{Variable(1)}}},
			// never true, so no facts are produced and nothing else dominates
			Expressions: []Expression{{Value{Variable(0)}, Value{Integer(-1)}, BinaryOp{Equal{}}}},
		})
		return w, syms
	}, budget, ErrWorldRunLimitTimeout)

	// combine finishes under budget, then apply materialises |q|^2 facts with
	// O(n^2) FactSet.Insert and Run does InsertAll: no deadline check anywhere.
	measureOvershoot(t, "materialise n^2 facts", func() (*World, *SymbolTable) {
		syms := &SymbolTable{}
		q, p := syms.Insert("q"), syms.Insert("p")
		w := NewWorld(WithMaxDuration(budget))
		for i := range 40 {
			w.AddFact(Fact{Predicate{q, []Term{Integer(i)}}})
		}
		w.AddRule(Rule{
			Head: Predicate{p, []Term{Variable(0), Variable(1)}},
			Body: []Predicate{{q, []Term{Variable(0)}}, {q, []Term{Variable(1)}}},
		})
		return w, syms
	}, budget, ErrWorldRunLimitMaxFacts, ErrWorldRunLimitTimeout)
}
