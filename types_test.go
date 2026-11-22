// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/stretchr/testify/require"
)

func TestFromDatalogFact(t *testing.T) {
	now := time.Now()

	symbolTable := &datalog.SymbolTable{"sym0", "sym1", "var1"}
	dlFact := datalog.Fact{
		Predicate: datalog.Predicate{
			Name: datalog.String(datalog.OFFSET + 0),
			Terms: []datalog.Term{
				datalog.String(datalog.OFFSET + 1),
				datalog.Integer(42),
				symbolTable.Insert("foo"),
				datalog.Variable(datalog.OFFSET + 2),
				datalog.Date(now.Unix()),
				datalog.Bytes([]byte("some random bytes")),
				datalog.Bool(true),
				datalog.Bool(false),
				datalog.Set{
					symbolTable.Insert("abc"),
					datalog.Integer(42),
					datalog.String(datalog.OFFSET + 1),
				},
			},
		},
	}

	fact, err := fromDatalogFact(symbolTable, dlFact)
	require.NoError(t, err)

	expectedFact := &Fact{
		Predicate: Predicate{
			Name: "sym0",
			IDs: []Term{
				String("sym1"),
				Integer(42),
				String("foo"),
				Variable("var1"),
				Date(time.Unix(now.Unix(), 0)),
				Bytes([]byte("some random bytes")),
				Bool(true),
				Bool(false),
				Set{String("abc"), Integer(42), String("sym1")},
			},
		},
	}
	require.Equal(t, expectedFact, fact)
}

// A date of a builder prints in UTC, as the date of a block does, whatever
// the zone of the Go value.
func TestDatePrintsUTC(t *testing.T) {
	zone := time.FixedZone("UTC+2", 2*60*60)
	date := Date(time.Date(2020, 1, 1, 2, 0, 0, 0, zone))
	require.Equal(t, "2020-01-01T00:00:00Z", date.String())

	symbols := &datalog.SymbolTable{}
	require.Equal(t, date.String(), datalog.SymbolDebugger{SymbolTable: symbols}.Term(date.convert(symbols)))
}

// The builders give the strings their symbols in the order of biscuit-rust,
// so that the same source gives the same symbol table, and thus the same
// print of a set of strings: the name of a predicate before its terms, the
// head of a rule before its body, the elements of a set by value, the
// integer keys of a map before its string keys.
func TestConvertSymbolOrder(t *testing.T) {
	symbols := func(convert func(*datalog.SymbolTable)) []string {
		syms := &datalog.SymbolTable{}
		convert(syms)
		return *syms
	}

	require.Equal(t, []string{"f", "b", "a"}, symbols(func(s *datalog.SymbolTable) {
		Predicate{Name: "f", IDs: []Term{String("b"), String("a")}}.convert(s)
	}))
	require.Equal(t, []string{"r", "x", "f", "b"}, symbols(func(s *datalog.SymbolTable) {
		Rule{
			Head: Predicate{Name: "r", IDs: []Term{Variable("x")}},
			Body: []Predicate{{Name: "f", IDs: []Term{Variable("x"), String("b")}}},
		}.convert(s)
	}))
	require.Equal(t, []string{"a", "b", "c"}, symbols(func(s *datalog.SymbolTable) {
		Set{String("c"), String("a"), String("b"), String("a")}.convert(s)
	}))
	require.Equal(t, []string{"y", "x", "a", "w", "b", "v"}, symbols(func(s *datalog.SymbolTable) {
		Map{{String("b"), String("v")}, {Integer(3), String("x")}, {String("a"), String("w")}, {Integer(1), String("y")}}.convert(s)
	}))
	// A key given twice keeps its last value: the other value has no symbol.
	require.Equal(t, []string{"a", "kept"}, symbols(func(s *datalog.SymbolTable) {
		Map{{String("a"), String("dropped")}, {String("a"), String("kept")}}.convert(s)
	}))

	// The set has the order of the symbols, and not that of the text, when
	// a string had its symbol before.
	syms := &datalog.SymbolTable{}
	b := syms.Insert("b")
	set := Set{String("b"), String("a")}.convert(syms)
	require.Equal(t, datalog.Set{b, syms.Insert("a")}, set)

	// The builder prints a set and a map as the block has them.
	require.Equal(t, "{-1, 9, 10}", Set{Integer(10), Integer(9), Integer(-1), Integer(9)}.String())
	require.Equal(t, `{1: "x", "a": 2, "b": 3}`, Map{
		{String("b"), Integer(1)}, {String("a"), Integer(2)}, {String("b"), Integer(3)}, {Integer(1), String("x")},
	}.String())
}
