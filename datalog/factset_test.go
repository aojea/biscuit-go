// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// factKey must agree with Predicate.Equal in both directions, including the
// Set cases where Equal is order and repetition insensitive but length sensitive.
func TestFactKeyMatchesEqual(t *testing.T) {
	p := String(1)
	preds := []Predicate{
		{p, []Term{Integer(1)}},
		{p, []Term{Integer(2)}},
		{String(2), []Term{Integer(1)}},
		{p, []Term{Integer(1), Integer(1)}},
		{p, []Term{Variable(1)}},
		{p, []Term{String(1)}},
		{p, []Term{Date(1)}},
		{p, []Term{Bool(true)}},
		{p, []Term{Bool(false)}},
		{p, []Term{Bytes{0x01}}},
		{p, []Term{Bytes{0x01, 0x00}}},
		{p, []Term{Bytes{0x01}, Bytes{}}},
		{p, []Term{Bytes{}, Bytes{0x01}}},
		{p, []Term{Set{Integer(1), Integer(2)}}},
		{p, []Term{Set{Integer(2), Integer(1)}}},
		{p, []Term{Set{Integer(1), Integer(1), Integer(2)}}},
		{p, []Term{Set{Integer(2), Integer(2), Integer(1)}}},
		{p, []Term{Set{Integer(1)}}},
		{p, []Term{Set{Integer(1), Integer(1)}}},
		{p, []Term{Set{Bytes{0x01}, Bytes{0x02}}}},
		{p, []Term{Set{Bytes{0x02}, Bytes{0x01}}}},
		{p, []Term{Set{}}},
		{p, []Term{Set{Set{Integer(1)}}}},
		{p, []Term{Set{Set{Integer(1)}, Set{Integer(1)}}}},
	}

	for i, a := range preds {
		for j, b := range preds {
			eq := a.Equal(b)
			require.Equal(t, eq, b.Equal(a), "Equal must be symmetric for %d/%d", i, j)
			ka, kb := string(factKey(nil, a)), string(factKey(nil, b))
			require.Equal(t, eq, ka == kb, "key equality must match Equal for %v / %v", a, b)
		}
	}
}

func TestWorldAddFactDedupMatchesInsert(t *testing.T) {
	facts := []Fact{
		{Predicate{String(1), []Term{Set{Integer(1), Integer(2)}}}},
		{Predicate{String(1), []Term{Set{Integer(2), Integer(1)}}}},
		{Predicate{String(1), []Term{Set{Integer(1), Integer(1), Integer(2)}}}},
		{Predicate{String(1), []Term{Bytes{0x01}}}},
		{Predicate{String(1), []Term{Bytes{0x01}}}},
	}
	// enough distinct facts to cross indexThreshold, each added twice
	for i := range 2 * indexThreshold {
		f := Fact{Predicate{String(2), []Term{Integer(i)}}}
		facts = append(facts, f, f)
	}

	w := NewWorld()
	linear := &FactSet{}
	for _, f := range facts {
		w.AddFact(f)
		linear.Insert(f)
	}
	require.Equal(t, *linear, *w.Facts())

	// a clone keeps deduplicating against the inherited facts, in both modes
	for _, w := range []*World{w.Clone(), NewWorld()} {
		for _, f := range facts {
			w.AddFact(f)
		}
		require.Equal(t, *linear, *w.Facts())
	}
	require.Equal(t, *linear, *w.Facts())
}

// A lookup through the index must find the same facts a linear scan does,
// whichever term is bound: constants, variables bound at an earlier level,
// and terms whose Equal is structural.
func TestCandidatesMatchLinearScan(t *testing.T) {
	syms := &SymbolTable{}
	p, q := syms.Insert("p"), syms.Insert("q")
	set := Set{Integer(1), Integer(2)}
	facts := &FactSet{
		{Predicate{p, []Term{Integer(1), String(1)}}},
		{Predicate{p, []Term{Integer(2), String(1)}}},
		{Predicate{p, []Term{Integer(1), String(2)}}},
		{Predicate{p, []Term{Set{Integer(2), Integer(1)}, String(2)}}},
		{Predicate{p, []Term{Bytes{1}, String(2)}}},
		{Predicate{p, []Term{Bool(true)}}},
		{Predicate{q, []Term{Integer(1), String(1)}}},
	}
	one := Term(Integer(1))

	for _, tc := range []struct {
		pred Predicate
		vars MatchedVariables
		want []int
	}{
		{Predicate{p, []Term{Variable(0), Variable(1)}}, nil, []int{0, 1, 2, 3, 4, 5}},
		{Predicate{p, []Term{Integer(1), Variable(1)}}, nil, []int{0, 2}},
		{Predicate{p, []Term{Variable(0), String(1)}}, nil, []int{0, 1}},
		{Predicate{p, []Term{Variable(0), Variable(1)}}, MatchedVariables{Variable(0): &one}, []int{0, 2}},
		{Predicate{p, []Term{set, Variable(1)}}, nil, []int{3}},
		{Predicate{p, []Term{Bytes{1}, Variable(1)}}, nil, []int{4}},
		{Predicate{p, []Term{Bool(true)}}, nil, []int{5}},
		{Predicate{p, []Term{Integer(3), Variable(1)}}, nil, nil},
		{Predicate{String(99), []Term{Variable(0)}}, nil, nil},
	} {
		got := newFactIndex(facts).candidates(tc.pred, tc.vars)
		require.Equal(t, tc.want, got, "%v", tc.pred)
	}
}

// A fact holding a variable matches nothing, as in biscuit-rust's
// match_preds; a token could otherwise carry a wildcard fact.
func TestFactWithVariableMatchesNothing(t *testing.T) {
	syms := &SymbolTable{}
	right := syms.Insert("right")
	ok := syms.Insert("ok")
	file := syms.Insert("file")
	read := syms.Insert("read")

	w := NewWorld()
	w.AddFact(Fact{Predicate{right, []Term{Variable(7), Variable(8)}}})

	for _, body := range []Predicate{
		{right, []Term{file, read}},
		{right, []Term{Variable(0), read}},
		{right, []Term{Variable(0), Variable(1)}},
	} {
		res := w.QueryRule(Rule{Head: Predicate{ok, nil}, Body: []Predicate{body}}, syms)
		require.Empty(t, *res, "%v", body)
	}

	w.AddFact(Fact{Predicate{right, []Term{file, read}}})
	res := w.QueryRule(Rule{Head: Predicate{ok, []Term{Variable(0)}}, Body: []Predicate{{right, []Term{Variable(0), Variable(1)}}}}, syms)
	require.Equal(t, FactSet{{Predicate{ok, []Term{file}}}}, *res)
}

func TestWorldCloneDoesNotShareFacts(t *testing.T) {
	fact := func(i int) Fact { return Fact{Predicate{String(1), []Term{Integer(i)}}} }
	w := NewWorld()
	// three facts leave spare capacity, so a shared backing array would overlap
	for i := range 3 {
		w.AddFact(fact(i))
	}

	c := w.Clone()
	c.AddFact(fact(10))
	w.AddFact(fact(20))

	require.Equal(t, FactSet{fact(0), fact(1), fact(2), fact(10)}, *c.Facts())
	require.Equal(t, FactSet{fact(0), fact(1), fact(2), fact(20)}, *w.Facts())
}
