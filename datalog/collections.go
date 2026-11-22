// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Array is an ordered sequence of terms of any type (datalog v3.3).
type Array []Term

func (Array) Type() TermType { return TermTypeArray }

func (a Array) Equal(t Term) bool {
	other, ok := t.(Array)
	if !ok || len(a) != len(other) {
		return false
	}
	for i := range a {
		if !a[i].Equal(other[i]) {
			return false
		}
	}
	return true
}

// HasPrefix reports whether a starts with the elements of prefix.
func (a Array) HasPrefix(prefix Array) bool {
	if len(prefix) > len(a) {
		return false
	}
	return Array(a[:len(prefix)]).Equal(prefix)
}

// HasSuffix reports whether a ends with the elements of suffix.
func (a Array) HasSuffix(suffix Array) bool {
	if len(suffix) > len(a) {
		return false
	}
	return Array(a[len(a)-len(suffix):]).Equal(suffix)
}

func (a Array) contains(t Term) bool {
	for _, e := range a {
		if e.Equal(t) {
			return true
		}
	}
	return false
}

func (a Array) String() string {
	strs := make([]string, len(a))
	for i, e := range a {
		strs[i] = e.String()
	}
	return fmt.Sprintf("[%s]", strings.Join(strs, ", "))
}

// MapEntry is one key/value pair of a Map. The key is an Integer or a
// String.
type MapEntry struct {
	Key   Term
	Value Term
}

// Map associates Integer or String keys with terms of any type (datalog
// v3.3). Entries are kept sorted by key, integers first, so that two maps
// with the same entries are equal and print the same.
type Map []MapEntry

// NewMap builds a map; a key given twice keeps its last value.
func NewMap(entries ...MapEntry) Map {
	m := make(Map, len(entries))
	copy(m, entries)
	slices.SortStableFunc(m, func(a, b MapEntry) int { return compareMapKeys(a.Key, b.Key) })
	// Entries with the same key are next to each other, in the order given.
	res := m[:0]
	for i, e := range m {
		if i+1 < len(m) && compareMapKeys(e.Key, m[i+1].Key) == 0 {
			continue
		}
		res = append(res, e)
	}
	return res
}

// compareMapKeys orders integers before strings, then by value.
func compareMapKeys(a, b Term) int {
	switch ka := a.(type) {
	case Integer:
		if kb, ok := b.(Integer); ok {
			return cmp.Compare(ka, kb)
		}
		return -1
	case String:
		if kb, ok := b.(String); ok {
			return cmp.Compare(ka, kb)
		}
		return 1
	default:
		return 0
	}
}

// IsMapKey reports whether a term may be a map key.
func IsMapKey(t Term) bool {
	switch t.(type) {
	case Integer, String:
		return true
	}
	return false
}

// compareTerms orders terms as biscuit-rust does: by type, in the order of
// the TermType values, then by value. A string has the order of its index in
// the symbol table, not of its text. This is the order of the elements of a
// set.
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
			return cmp.Compare(a, b)
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
			return slices.CompareFunc(sortedSet(a), sortedSet(b), compareTerms)
		}
	case Array:
		if b, ok := b.(Array); ok {
			return slices.CompareFunc(a, b, compareTerms)
		}
	case Map:
		if b, ok := b.(Map); ok {
			return slices.CompareFunc(a, b, func(x, y MapEntry) int {
				if c := compareMapKeys(x.Key, y.Key); c != 0 {
					return c
				}
				return compareTerms(x.Value, y.Value)
			})
		}
	}
	return 0
}

// sortedSet returns the elements of the set in the order of compareTerms.
// It does not change the set.
func sortedSet(s Set) Set {
	if slices.IsSortedFunc(s, compareTerms) {
		return s
	}
	sorted := slices.Clone(s)
	slices.SortStableFunc(sorted, compareTerms)
	return sorted
}

// NewSet builds a set as biscuit-rust keeps it: an element given more than
// once is in the set once, and the elements are in the order of their type
// and value, where a string has the order of its index in the symbol table.
func NewSet(elements ...Term) Set {
	s := make(Set, len(elements))
	copy(s, elements)
	slices.SortStableFunc(s, compareTerms)
	return slices.CompactFunc(s, func(a, b Term) bool { return a.Equal(b) })
}

func (Map) Type() TermType { return TermTypeMap }

func (m Map) Equal(t Term) bool {
	other, ok := t.(Map)
	if !ok || len(m) != len(other) {
		return false
	}
	for i := range m {
		if !m[i].Key.Equal(other[i].Key) || !m[i].Value.Equal(other[i].Value) {
			return false
		}
	}
	return true
}

// Get returns the value for the key, or nil when absent.
func (m Map) Get(key Term) Term {
	for _, e := range m {
		if e.Key.Equal(key) {
			return e.Value
		}
	}
	return nil
}

func (m Map) String() string {
	strs := make([]string, len(m))
	for i, e := range m {
		strs[i] = fmt.Sprintf("%s: %s", e.Key, e.Value)
	}
	return fmt.Sprintf("{%s}", strings.Join(strs, ", "))
}
