// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"fmt"
	"testing"
	"time"
)

// benchWorld lifts the default run limits, which are sized for tokens, not benchmarks.
func benchWorld() *World {
	return NewWorld(WithMaxDuration(time.Minute), WithMaxFacts(1<<20), WithMaxIterations(1<<20))
}

// A chain of n nodes; path is the transitive closure of edge.
// Exercises the fixpoint loop and the join on a recursive rule.
func BenchmarkWorldRunTransitiveClosure(b *testing.B) {
	for _, n := range []int{8, 16, 24} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			syms := &SymbolTable{}
			edge := syms.Insert("edge")
			path := syms.Insert("path")

			facts := make([]Fact, 0, n)
			for i := 0; i < n-1; i++ {
				facts = append(facts, Fact{Predicate{edge, []Term{Integer(i), Integer(i + 1)}}})
			}
			rules := []Rule{
				{
					Head: Predicate{path, []Term{Variable(0), Variable(1)}},
					Body: []Predicate{{edge, []Term{Variable(0), Variable(1)}}},
				},
				{
					Head: Predicate{path, []Term{Variable(0), Variable(2)}},
					Body: []Predicate{
						{path, []Term{Variable(0), Variable(1)}},
						{edge, []Term{Variable(1), Variable(2)}},
					},
				},
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := benchWorld()
				for _, f := range facts {
					w.AddFact(NewOrigin(0), f)
				}
				for _, r := range rules {
					w.AddRule(0, DefaultTrustedOrigins(), r)
				}
				if err := w.Run(syms); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Three-way join over 3n facts through Run. c(-1) matches no fact, so combine
// walks 3n³ steps without a single full match: no allocations, the scan cost
// (including the deadline budget) dominates.
func BenchmarkWorldRunJoin(b *testing.B) {
	for _, n := range []int{50, 100, 200} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			syms := &SymbolTable{}
			a := syms.Insert("a")
			bb := syms.Insert("b")
			c := syms.Insert("c")
			abc := syms.Insert("abc")

			facts := make([]Fact, 0, 3*n)
			for i := range n {
				for _, p := range []String{a, bb, c} {
					facts = append(facts, Fact{Predicate{p, []Term{Integer(i)}}})
				}
			}
			rule := Rule{
				Head: Predicate{abc, []Term{Variable(0), Variable(1)}},
				Body: []Predicate{
					{a, []Term{Variable(0)}},
					{bb, []Term{Variable(1)}},
					{c, []Term{Integer(-1)}},
				},
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := benchWorld()
				for _, f := range facts {
					w.AddFact(NewOrigin(0), f)
				}
				w.AddRule(0, DefaultTrustedOrigins(), rule)
				if err := w.Run(syms); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Inserting n distinct facts; FactSet.Insert scans for duplicates on each insert.
func BenchmarkWorldAddFact(b *testing.B) {
	for _, n := range []int{100, 1000} {
		b.Run(fmt.Sprintf("facts=%d", n), func(b *testing.B) {
			syms := &SymbolTable{}
			right := syms.Insert("right")
			read := syms.Insert("read")
			facts := make([]Fact, n)
			for i := range facts {
				facts[i] = Fact{Predicate{right, []Term{syms.Insert(fmt.Sprintf("/file%d", i)), read}}}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := benchWorld()
				for _, f := range facts {
					w.AddFact(NewOrigin(0), f)
				}
			}
		})
	}
}

// A typical authorization check: three body predicates joined over n rights.
func BenchmarkWorldQueryRule(b *testing.B) {
	for _, n := range []int{10, 100} {
		b.Run(fmt.Sprintf("rights=%d", n), func(b *testing.B) {
			syms := &SymbolTable{}
			right := syms.Insert("right")
			resource := syms.Insert("resource")
			operation := syms.Insert("operation")
			check := syms.Insert("check")
			read := syms.Insert("read")

			w := benchWorld()
			for i := range n {
				w.AddFact(NewOrigin(0), Fact{Predicate{right, []Term{syms.Insert(fmt.Sprintf("/file%d", i)), read}}})
			}
			w.AddFact(NewOrigin(0), Fact{Predicate{resource, []Term{syms.Insert(fmt.Sprintf("/file%d", n-1))}}})
			w.AddFact(NewOrigin(0), Fact{Predicate{operation, []Term{read}}})

			query := Rule{
				Head: Predicate{check, []Term{Variable(0)}},
				Body: []Predicate{
					{resource, []Term{Variable(0)}},
					{operation, []Term{Variable(1)}},
					{right, []Term{Variable(0), Variable(1)}},
				},
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := w.QueryRule(query, 0, DefaultTrustedOrigins(), syms)
				if err != nil || len(*res) != 1 {
					b.Fatalf("got %d results (%v), want 1", len(*res), err)
				}
			}
		})
	}
}

// The same check with QueryMatch, which the authorizer uses for a check and
// a policy: it reads the facts in the order of biscuit-rust and stops at
// the first match. The facts are added in another order than the sorted
// one. The world sorts them for its first query ("first") and the queries
// after it read the sorted copy ("next").
func BenchmarkWorldQueryMatch(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		syms := &SymbolTable{}
		right := syms.Insert("right")
		resource := syms.Insert("resource")
		operation := syms.Insert("operation")
		check := syms.Insert("check")
		read := syms.Insert("read")
		files := make([]Term, n)
		for i := range n {
			files[i] = syms.Insert(fmt.Sprintf("/file%d", i))
		}

		w := benchWorld()
		for i := range n {
			// 7919 is a prime: each file is added one time.
			w.AddFact(NewOrigin(0), Fact{Predicate{right, []Term{files[i*7919%n], read}}})
		}
		w.AddFact(NewOrigin(0), Fact{Predicate{resource, []Term{files[n-1]}}})
		w.AddFact(NewOrigin(0), Fact{Predicate{operation, []Term{read}}})

		queries := []struct {
			name string
			rule Rule
		}{
			// check if resource($f), operation($op), right($f, $op)
			{"join", Rule{
				Head: Predicate{check, nil},
				Body: []Predicate{
					{resource, []Term{Variable(0)}},
					{operation, []Term{Variable(1)}},
					{right, []Term{Variable(0), Variable(1)}},
				},
			}},
			// check if right("/file<n-1>", "read")
			{"one", Rule{
				Head: Predicate{check, nil},
				Body: []Predicate{{right, []Term{files[n-1], read}}},
			}},
		}
		for _, query := range queries {
			b.Run(fmt.Sprintf("%s/rights=%d/first", query.name, n), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					fresh := w.Clone()
					b.StartTimer()
					matched, err := fresh.QueryMatch(query.rule, DefaultTrustedOrigins(), syms)
					if err != nil || !matched {
						b.Fatalf("got %v (%v), want a match", matched, err)
					}
				}
			})
			b.Run(fmt.Sprintf("%s/rights=%d/next", query.name, n), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					matched, err := w.QueryMatch(query.rule, DefaultTrustedOrigins(), syms)
					if err != nil || !matched {
						b.Fatalf("got %v (%v), want a match", matched, err)
					}
				}
			})
		}
	}
}

func BenchmarkSetEqual(b *testing.B) {
	const n = 10
	strs := make(Set, n)
	byts := make(Set, n)
	for i := range n {
		strs[i] = String(i)
		byts[i] = Bytes{byte(i), byte(i >> 8)}
	}
	// Reversed copies so no element sits at the same index in both sets.
	reversed := func(s Set) Set {
		r := make(Set, len(s))
		for i := range s {
			r[len(s)-1-i] = s[i]
		}
		return r
	}

	cases := []struct {
		name string
		a, b Set
	}{
		{"strings", strs, reversed(strs)},
		{"bytes", byts, reversed(byts)},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !c.a.Equal(c.b) {
					b.Fatal("sets should be equal")
				}
			}
		})
	}
}

// $a + 2 < 4 with $a bound to 1.
func BenchmarkExpressionEvaluate(b *testing.B) {
	syms := &SymbolTable{}
	var a Term = Integer(1)
	values := map[Variable]*Term{0: &a}
	expr := Expression{
		Value{Variable(0)},
		Value{Integer(2)},
		BinaryOp{Add{}},
		Value{Integer(4)},
		BinaryOp{LessThan{}},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		res, err := expr.Evaluate(values, syms)
		if err != nil || !res.Equal(Bool(true)) {
			b.Fatal(res, err)
		}
	}
}

// A map term of a token is read before the signatures are checked: the cost
// of NewMap must not grow with the square of the number of entries.
func BenchmarkNewMap(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		entries := make([]MapEntry, n)
		for i := range entries {
			// keys in reverse order, so that the map is not sorted yet
			entries[i] = MapEntry{Key: Integer(n - i), Value: Integer(i)}
		}
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if len(NewMap(entries...)) != n {
					b.Fatal("entries are missing")
				}
			}
		})
	}
}
