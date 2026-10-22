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
