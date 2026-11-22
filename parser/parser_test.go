// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	Input         string
	Expected      any
	ExpectFailure bool
	ExpectErr     error
}

func getFactTestCases() []testCase {
	return []testCase{
		{
			Input: `right("/a/file1.txt", "read", {"read", "/a/file2.txt"})`,
			Expected: biscuit.Fact{
				Predicate: biscuit.Predicate{
					Name: "right",
					IDs: []biscuit.Term{
						biscuit.String("/a/file1.txt"),
						biscuit.String("read"),
						biscuit.Set{
							biscuit.String("read"),
							biscuit.String("/a/file2.txt"),
						},
					},
				},
			},
		},
		{
			Input:         `right("/a/file1.txt", $0)`,
			ExpectFailure: true,
			ExpectErr:     ErrVariableInFact,
		},
		{
			Input:         `right("/a/file1.txt"`,
			ExpectFailure: true,
		},
		{
			Input:         `right(/a/file1.txt")`,
			ExpectFailure: true,
		},
		{
			Input:         `right("/a/file1.txt", [$0])`,
			ExpectFailure: true,
		},
		{
			Input:         `right("/a/file1.txt" "read")`,
			ExpectFailure: true,
		},
		{
			Input:         `right(1, 2 3, 4)`,
			ExpectFailure: true,
		},
		{
			Input:    `empty()`,
			Expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: "empty", IDs: []biscuit.Term{}}},
		},
		// Names starting with a method or literal keyword are still names.
		{
			Input:    `prefixed("a")`,
			Expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: "prefixed", IDs: []biscuit.Term{biscuit.String("a")}}},
		},
		{
			Input:    `lengthy(1)`,
			Expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: "lengthy", IDs: []biscuit.Term{biscuit.Integer(1)}}},
		},
		{
			Input:    `contains_x(1)`,
			Expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: "contains_x", IDs: []biscuit.Term{biscuit.Integer(1)}}},
		},
		{
			Input:    `matcheslist(1)`,
			Expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: "matcheslist", IDs: []biscuit.Term{biscuit.Integer(1)}}},
		},
		{
			Input:    `truename("x")`,
			Expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: "truename", IDs: []biscuit.Term{biscuit.String("x")}}},
		},
		{
			Input:    `falsehood(true)`,
			Expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: "falsehood", IDs: []biscuit.Term{biscuit.Bool(true)}}},
		},
	}
}

func getRuleTestCases() []testCase {
	t1, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	t2, _ := time.Parse(time.RFC3339, time.Now().Add(2*time.Second).Format(time.RFC3339))

	return []testCase{
		{
			Input: `grandparent("a", "c") <- parent($0, "b"), parent("b", $1), $0 > 42, $1.starts_with("abc")`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "grandparent",
					IDs: []biscuit.Term{
						biscuit.String("a"),
						biscuit.String("c"),
					},
				},
				Body: []biscuit.Predicate{
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.Variable("0"),
							biscuit.String("b"),
						},
					},
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.String("b"),
							biscuit.Variable("1"),
						},
					},
				},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Integer(42)},
						biscuit.BinaryGreaterThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.Value{Term: biscuit.String("abc")},
						biscuit.BinaryPrefix,
					},
				},
			},
		},
		{
			Input: `grandparent("a", "c") <- parent("a", "b"), parent("b", "c")`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "grandparent",
					IDs: []biscuit.Term{
						biscuit.String("a"),
						biscuit.String("c"),
					},
				},
				Body: []biscuit.Predicate{
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.String("a"),
							biscuit.String("b"),
						},
					},
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.String("b"),
							biscuit.String("c"),
						},
					},
				},
				Expressions: []biscuit.Expression{},
			},
		},
		{
			Input: fmt.Sprintf(`rule1("a") <- body1($0), $0 > %s, $0 < %s`, t1.Format(time.RFC3339), t2.Format(time.RFC3339)),

			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.Variable("0")},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Date(t1)},
						biscuit.BinaryGreaterThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Date(t2)},
						biscuit.BinaryLessThan,
					},
				},
			},
		},
		{
			Input:         fmt.Sprintf(`rule1("a") <- body1($0), $0 > %s`, t1.Format(time.RFC1123)),
			ExpectFailure: true,
		},
		{
			Input: `rule1("a") <- body1($0, $1, $2, $3, $4, $5, $6), $0 > 0, $1 < 1, $2 >= 2, $3 <= 3, $4 == 4, {1, 2, 3}.contains($5), !{4,5,6}.contains($6)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs: []biscuit.Term{
						biscuit.Variable("0"), biscuit.Variable("1"), biscuit.Variable("2"), biscuit.Variable("3"),
						biscuit.Variable("4"), biscuit.Variable("5"), biscuit.Variable("6"),
					},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Integer(0)},
						biscuit.BinaryGreaterThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.Value{Term: biscuit.Integer(1)},
						biscuit.BinaryLessThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("2")},
						biscuit.Value{Term: biscuit.Integer(2)},
						biscuit.BinaryGreaterOrEqual,
					},
					{
						biscuit.Value{Term: biscuit.Variable("3")},
						biscuit.Value{Term: biscuit.Integer(3)},
						biscuit.BinaryLessOrEqual,
					},
					{
						biscuit.Value{Term: biscuit.Variable("4")},
						biscuit.Value{Term: biscuit.Integer(4)},
						biscuit.BinaryHeterogeneousEqual,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.Integer(1), biscuit.Integer(2), biscuit.Integer(3)}},
						biscuit.Value{Term: biscuit.Variable("5")},
						biscuit.BinaryContains,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.Integer(4), biscuit.Integer(5), biscuit.Integer(6)}},
						biscuit.Value{Term: biscuit.Variable("6")},
						biscuit.BinaryContains,
						biscuit.UnaryNegate,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- body1($0, $1, $2, $3, $4, $5), $0 == "abc", $1.starts_with("def"), $2.ends_with("ghi"), $3.matches("file[0-9]+.txt"), {"a","b"}.contains($4), !{"c", "d"}.contains($5)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs: []biscuit.Term{
						biscuit.Variable("0"), biscuit.Variable("1"), biscuit.Variable("2"),
						biscuit.Variable("3"), biscuit.Variable("4"), biscuit.Variable("5"),
					},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.String("abc")},
						biscuit.BinaryHeterogeneousEqual,
					},
					{
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.Value{Term: biscuit.String("def")},
						biscuit.BinaryPrefix,
					},
					{
						biscuit.Value{Term: biscuit.Variable("2")},
						biscuit.Value{Term: biscuit.String("ghi")},
						biscuit.BinarySuffix,
					},
					{
						biscuit.Value{Term: biscuit.Variable("3")},
						biscuit.Value{Term: biscuit.String("file[0-9]+.txt")},
						biscuit.BinaryRegex,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.String("a"), biscuit.String("b")}},
						biscuit.Value{Term: biscuit.Variable("4")},
						biscuit.BinaryContains,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.String("c"), biscuit.String("d")}},
						biscuit.Value{Term: biscuit.Variable("5")},
						biscuit.BinaryContains,
						biscuit.UnaryNegate,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- body1($0, $1), {"a", "b"}.contains($0), !{"c", "d"}.contains($1)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Set{biscuit.String("a"), biscuit.String("b")}},
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.BinaryContains,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.String("c"), biscuit.String("d")}},
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.BinaryContains,
						biscuit.UnaryNegate,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- body1(hex:41414141)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.Bytes([]byte{0x41, 0x41, 0x41, 0x41})},
				}},
				Expressions: []biscuit.Expression{},
			},
		},
		{
			Input: `rule1("a") <- body1($0), $0 == hex:41414141`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.Variable("0")},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Bytes([]byte{0x41, 0x41, 0x41, 0x41})},
						biscuit.BinaryHeterogeneousEqual,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- body1($0, $1), {"abc", "def"}.contains($0), ! {41, 42}.contains($1)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Set{biscuit.String("abc"), biscuit.String("def")}},
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.BinaryContains,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.Integer(41), biscuit.Integer(42)}},
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.BinaryContains,
						biscuit.UnaryNegate,
					},
				},
			},
		},

		{
			Input: `empty() <- body1($0, $1)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "empty",
					IDs:  []biscuit.Term{},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")},
				}},
				Expressions: []biscuit.Expression{},
			},
		},
		{
			Input:         `grandparent(#a, #c) <-- parent(#a, #b), parent(#b, #c)`,
			ExpectFailure: true,
		},
		{
			Input:         `<- parent(#a, #b), parent(#b, #c)`,
			ExpectFailure: true,
		},
		{
			Input:         `rule1(#a) <- body1($0, $1), $0 in [$1, "foo"]`,
			ExpectFailure: true,
		},
		{
			// fails because precedence is not handled
			Input: `rule1("a") <- true || false && true`,

			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Bool(true)},
						biscuit.Closure{Body: biscuit.Expression{
							biscuit.Value{Term: biscuit.Bool(false)},
							biscuit.Closure{Body: biscuit.Expression{biscuit.Value{Term: biscuit.Bool(true)}}},
							biscuit.BinaryLazyAnd,
						}},
						biscuit.BinaryLazyOr,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- 1 + 2 * 3 + 4 / 5`,

			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Integer(1)},
						biscuit.Value{Term: biscuit.Integer(2)},
						biscuit.Value{Term: biscuit.Integer(3)},
						biscuit.BinaryMul,
						biscuit.BinaryAdd,
						biscuit.Value{Term: biscuit.Integer(4)},
						biscuit.Value{Term: biscuit.Integer(5)},
						biscuit.BinaryDiv,
						biscuit.BinaryAdd,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- 1 + 2 * (3 + 4)`,

			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Integer(1)},
						biscuit.Value{Term: biscuit.Integer(2)},
						biscuit.Value{Term: biscuit.Integer(3)},
						biscuit.Value{Term: biscuit.Integer(4)},
						biscuit.BinaryAdd,
						biscuit.UnaryParens,
						biscuit.BinaryMul,
						biscuit.BinaryAdd,
					},
				},
			},
		},
	}
}

func getCheckTestCases() []testCase {
	return []testCase{
		{
			Input: `check if parent("a", "b"), parent("b", "c"), {1,2,3}.contains($0) or right("read", "/a/file1.txt")`,
			Expected: biscuit.Check{
				Queries: []biscuit.Rule{
					{
						Head: biscuit.Predicate{
							Name: "query",
							IDs:  []biscuit.Term{},
						},
						Body: []biscuit.Predicate{
							{
								Name: "parent",
								IDs: []biscuit.Term{
									biscuit.String("a"),
									biscuit.String("b"),
								},
							},
							{
								Name: "parent",
								IDs: []biscuit.Term{
									biscuit.String("b"),
									biscuit.String("c"),
								},
							},
						},
						Expressions: []biscuit.Expression{
							{
								biscuit.Value{Term: biscuit.Set{biscuit.Integer(1), biscuit.Integer(2), biscuit.Integer(3)}},
								biscuit.Value{Term: biscuit.Variable("0")},
								biscuit.BinaryContains,
							},
						},
					},
					{
						Head: biscuit.Predicate{
							Name: "query",
							IDs:  []biscuit.Term{},
						},
						Body: []biscuit.Predicate{
							{
								Name: "right",
								IDs: []biscuit.Term{
									biscuit.String("read"),
									biscuit.String("/a/file1.txt"),
								},
							},
						},
						Expressions: []biscuit.Expression{},
					},
				},
			},
		},
		{
			Input:         `[ caveat1($0) <- parent(#a, #b), parent(#b, #c) @ $0 in [1,2,3]`,
			ExpectFailure: true,
		},
	}
}

func TestParserFact(t *testing.T) {
	p := New()
	for _, testCase := range getFactTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			fact, err := p.Fact(testCase.Input, nil)
			if testCase.ExpectFailure {
				if testCase.ExpectErr != nil {
					require.Equal(t, testCase.ExpectErr, err)
				} else {
					require.Error(t, err)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.Expected, fact)
			}
		})
	}
}

func TestParseRule(t *testing.T) {
	p := New()
	for _, testCase := range getRuleTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			rule, err := p.Rule(testCase.Input, nil)
			if testCase.ExpectFailure {
				if testCase.ExpectErr != nil {
					require.Equal(t, testCase.ExpectErr, err)
				} else {
					require.Error(t, err)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.Expected, rule)
			}
		})
	}
}

// A rule with a variable that no predicate of its body binds is refused, as
// in biscuit-rust: an authorizer refuses a token that has such a rule.
func TestParseRuleUnboundVariable(t *testing.T) {
	p := New()
	for input, unbound := range map[string]string{
		`right($file, $op) <- resource($file)`:                 "$op",
		`right($a, $b, $a) <- resource(1)`:                     "$a, $b",
		`right(1) <- true, $x`:                                 "$x",
		`right($file) <- resource($file), $size > 10`:          "$size",
		`right($file) <- resource($file), {1}.contains($size)`: "$size",
	} {
		_, err := p.Rule(input, nil)
		require.ErrorIs(t, err, ErrUnboundVariable, input)
		require.ErrorContains(t, err, ": "+unbound, input)

		_, err = p.Block(input+";", nil)
		require.ErrorIs(t, err, ErrUnboundVariable, input)
		_, err = p.Authorizer(input+";", nil)
		require.ErrorIs(t, err, ErrUnboundVariable, input)
	}

	for _, input := range []string{
		`right($file, "read") <- resource($file), owner($user, $file), $user != "eve"`,
		// the parameter of a closure, and the variables in its body
		`right($file) <- resource($file), [1, 2].all($p -> $p > 0)`,
		`right($file) <- resource($file), [1, 2].all($p -> $other > 0)`,
	} {
		_, err := p.Rule(input, nil)
		require.NoError(t, err, input)
	}

	// A check or a policy is not examined: its expression fails when the
	// authorizer evaluates it.
	_, err := p.Check(`check if resource($file), $size > 10`, nil)
	require.NoError(t, err)
	_, err = p.Policy(`allow if resource($file), $size > 10`, nil)
	require.NoError(t, err)
}

// A string has the escapes of biscuit-rust: \" \\ and \n. All other
// characters stand for themselves, a new line also, and no other escape is
// valid.
func TestParseStringEscapes(t *testing.T) {
	p := New()
	for input, want := range map[string]string{
		`""`:               ``,
		`"abc"`:            `abc`,
		`"a\"b"`:           `a"b`,
		`"é\""`:            `é"`,
		`"a\\b"`:           `a\b`,
		`"a\\"`:            `a\`,
		`"\\\""`:           `\"`,
		`"a\nb"`:           "a\nb",
		"\"a\nb\tc\"":      "a\nb\tc",
		`"http://x//y"`:    `http://x//y`,
		`"^\\d+\\.\\w+$"`:  `^\d+\.\w+$`,
		`"a;b) <- c // d"`: `a;b) <- c // d`,
	} {
		fact, err := p.Fact(`f(`+input+`)`, nil)
		require.NoError(t, err, input)
		require.Equal(t, []biscuit.Term{biscuit.String(want)}, fact.IDs, input)
	}

	// Two strings, and not one that has a quote in the middle.
	fact, err := p.Fact(`f("a\"", "b")`, nil)
	require.NoError(t, err)
	require.Equal(t, []biscuit.Term{biscuit.String(`a"`), biscuit.String("b")}, fact.IDs)

	// The error names the escape at each place where a string can be.
	for _, input := range []string{`"a\tb"`, `"\w+"`, `"\u00e9"`, `"\x41"`, `"\r"`, `"\0"`, `"\'"`} {
		_, err := p.Fact(`f(`+input+`)`, nil)
		require.ErrorContains(t, err, "invalid escape in the string "+input, input)
		_, err = p.Check(`check if f($s), $s.matches(`+input+`)`, nil)
		require.ErrorContains(t, err, "invalid escape in the string "+input, input)
		_, err = p.Block(`f(1); g({"a": [`+input+`]});`, nil)
		require.ErrorContains(t, err, "invalid escape in the string "+input, input)
	}
	for _, input := range []string{"\"a\\\nb\"", `"abc\"`, `"abc`} {
		_, err := p.Fact(`f(`+input+`)`, nil)
		require.Error(t, err, input)
	}
}

// The printers write a string as source: the parser gives the same string
// back, also when it has a quote or a backslash. biscuit-rust prints such a
// string as it is, and its source then parses to something else, or not at
// all.
func TestPrintedStringParses(t *testing.T) {
	p := New()
	for _, s := range []string{`abc`, `a"b`, `a\b`, `\`, `"`, `\"`, `\n`, "a\nb", `^\d+\.\w+$`, `é"`, `a", "b`, `hex:00`} {
		fact := biscuit.Fact{Predicate: biscuit.Predicate{Name: "f", IDs: []biscuit.Term{biscuit.String(s)}}}

		parsed, err := p.Fact(fact.String(), nil)
		require.NoError(t, err, s)
		require.Equal(t, fact, parsed, s)

		syms := &datalog.SymbolTable{}
		printed := datalog.SymbolDebugger{SymbolTable: syms}.Term(syms.Insert(s))
		parsed, err = p.Fact("f("+printed+")", nil)
		require.NoError(t, err, s)
		require.Equal(t, fact, parsed, s)
	}
}

// The content of a string is not syntax. A string that reads as a token of
// the language stays a string: "hex:00" is not bytes and {","} is not the
// empty set. A string cannot stand for a separator, an operator or a name.
func TestParseStringIsNotSyntax(t *testing.T) {
	p := New()
	for _, s := range []string{
		`hex:00`, `hex:zz`, `,`, `}`, `{`, `[`, `null`, `true`, `-`, `!`, `(`, `)`, `;`, `:`, `or`,
		`trusting`, `check if`, `==`, `<-`, `$x`, `// c`, `1`, `2020-01-01T00:00:00Z`, `ed25519/00`,
	} {
		str := biscuit.String(s)

		fact, err := p.Fact(`f("`+s+`")`, nil)
		require.NoError(t, err, s)
		require.Equal(t, []biscuit.Term{str}, fact.IDs, s)

		fact, err = p.Fact(`f({"`+s+`"}, ["`+s+`"], {"`+s+`": "`+s+`"})`, nil)
		require.NoError(t, err, s)
		require.Equal(t, []biscuit.Term{
			biscuit.Set{str}, biscuit.Array{str}, biscuit.Map{{Key: str, Value: str}},
		}, fact.IDs, s)

		check, err := p.Check(`check if "`+s+`" == "`+s+`"`, nil)
		require.NoError(t, err, s)
		expression := check.Queries[0].Expressions[0]
		require.Len(t, expression, 3, s)
		require.Equal(t, biscuit.Value{Term: str}, expression[0], s)
		require.Equal(t, biscuit.Value{Term: str}, expression[1], s)
	}

	for _, input := range []string{
		`check if f("a" "," "b")`,
		`check if 1 "==" 1`,
		`check if f(1) "or" g(1)`,
		`check if "a"."length"() == 1`,
		`check if f("(" 1 ")")`,
		`check if "!" true`,
	} {
		_, err := p.Check(input, nil)
		require.Error(t, err, input)
	}
}

// A fact in the source of a block or of an authorizer cannot have a
// variable, as a fact parsed on its own.
func TestParseBlockFactWithVariable(t *testing.T) {
	p := New()
	_, err := p.Block(`right("file1", "read"); right($file, "read");`, nil)
	require.ErrorIs(t, err, ErrVariableInFact)
	_, err = p.Authorizer(`resource($file); allow if true;`, nil)
	require.ErrorIs(t, err, ErrVariableInFact)

	_, err = p.Block(`right("file1", "read"); right($file, "read") <- resource($file);`, nil)
	require.NoError(t, err)
}

// `!` applies to what comes after it up to the level of `+` and `-`, as in
// biscuit-rust: the same source gives the same operations.
func TestParseNegationGroups(t *testing.T) {
	p := New()
	value := func(i int64) biscuit.Op { return biscuit.Value{Term: biscuit.Integer(i)} }
	variable := func(name string) biscuit.Op { return biscuit.Value{Term: biscuit.Variable(name)} }
	truth := biscuit.Value{Term: biscuit.Bool(true)}

	for source, want := range map[string]biscuit.Expression{
		// !(1 + 2)
		`!1 + 2`: {value(1), value(2), biscuit.BinaryAdd, biscuit.UnaryNegate},
		// !((1 * 2) - 3)
		`!1 * 2 - 3`: {value(1), value(2), biscuit.BinaryMul, value(3), biscuit.BinarySub, biscuit.UnaryNegate},
		// 1 * !(2 + 3)
		`1 * !2 + 3`: {value(1), value(2), value(3), biscuit.BinaryAdd, biscuit.UnaryNegate, biscuit.BinaryMul},
		// (!$a) == $b, (!$a) & $b
		`f($a, $b), !$a == $b`: {variable("a"), biscuit.UnaryNegate, variable("b"), biscuit.BinaryHeterogeneousEqual},
		`f($a, $b), !$a & $b`:  {variable("a"), biscuit.UnaryNegate, variable("b"), biscuit.BinaryBitwiseAnd},
		// !($a.length())
		`f($a), !$a.length()`: {variable("a"), biscuit.UnaryLength, biscuit.UnaryNegate},
		`!!true`:              {truth, biscuit.UnaryNegate, biscuit.UnaryNegate},
		// the parentheses are an operation of their own
		`(!1) + 2`: {value(1), biscuit.UnaryNegate, biscuit.UnaryParens, value(2), biscuit.BinaryAdd},
	} {
		check, err := p.Check("check if "+source, nil)
		require.NoError(t, err, source)
		expressions := check.Queries[0].Expressions
		require.Equal(t, want, expressions[len(expressions)-1], source)
	}
}

// The parser calls itself for each level of nesting. A source that is
// nested too deep is refused before the parser reads it: without the limit
// it stops the process with a stack overflow, which no caller can recover.
func TestParseNestingLimit(t *testing.T) {
	p := New()
	deep := 100000
	for name, source := range map[string]string{
		"parentheses": "check if " + strings.Repeat("(", deep),
		"negations":   "check if " + strings.Repeat("!", deep) + "true",
		"arrays":      "check if f(" + strings.Repeat("[", deep),
		"braces":      "check if f(" + strings.Repeat("{", deep),
		"mixed":       "check if " + strings.Repeat("!(", deep),
		"sum":         "check if " + strings.Repeat("!1 + ", deep) + "1",
	} {
		_, err := p.Check(source, nil)
		require.ErrorIs(t, err, ErrNestingTooDeep, name)
		_, err = p.Block(source+";", nil)
		require.ErrorIs(t, err, ErrNestingTooDeep, name)
		_, err = p.Authorizer(source+";", nil)
		require.ErrorIs(t, err, ErrNestingTooDeep, name)
	}

	// Under the limit, and what is not nesting: a string, a comment, and
	// the statements of a block, each with its own `!`.
	for name, source := range map[string]string{
		"parentheses": "check if " + strings.Repeat("(", 200) + "true" + strings.Repeat(")", 200) + ";",
		"negations":   "check if " + strings.Repeat("!", 200) + "true;",
		"string":      `f("` + strings.Repeat("(!", deep) + `");`,
		"comment":     "// " + strings.Repeat("(!", deep) + "\nf(1);",
		"statements":  strings.Repeat("check if !false;\n", 1000),
	} {
		_, err := p.Block(source, nil)
		require.NoError(t, err, name)
	}
}

func TestParserCheck(t *testing.T) {
	p := New()
	for _, testCase := range getCheckTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			caveat, err := p.Check(testCase.Input, nil)
			if testCase.ExpectFailure {
				if testCase.ExpectErr != nil {
					require.Equal(t, testCase.ExpectErr, err)
				} else {
					require.Error(t, err)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.Expected, caveat)
			}
		})
	}
}

// A check parsed on its own keeps its kind: `reject if` read as `check if`
// would pass when it must fail.
func TestParserCheckKind(t *testing.T) {
	for input, kind := range map[string]biscuit.CheckKind{
		`check if resource("file1")`:      biscuit.CheckKindOne,
		`check all resource($r), $r != 1`: biscuit.CheckKindAll,
		`reject if resource("file1")`:     biscuit.CheckKindReject,
	} {
		check, err := FromStringCheck(input)
		require.NoError(t, err)
		require.Equal(t, kind, check.Kind, input)

		block, err := FromStringBlock(input + ";")
		require.NoError(t, err)
		require.Equal(t, block.Checks[0], check, input)
	}
}

func TestMustParserFact(t *testing.T) {
	p := New()
	for _, testCase := range getFactTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			if testCase.ExpectFailure {
				defer func() {
					r := recover()
					require.NotNil(t, r)
				}()
			}

			fact := p.Must().Fact(testCase.Input, nil)
			require.Equal(t, testCase.Expected, fact)
		})
	}
}

// func TestMustParseRule(t *testing.T) {
// 	p := New()
// 	for _, testCase := range getRuleTestCases() {
// 		t.Run(testCase.Input, func(t *testing.T) {
// 			if testCase.ExpectFailure {
// 				defer func() {
// 					r := recover()
// 					require.NotNil(t, r)
// 				}()
// 			}
// 			rule := p.Must().Rule(testCase.Input)
// 			require.Equal(t, testCase.Expected, rule)
// 		})
// 	}
// }

// func TestMustParserCaveat(t *testing.T) {
// 	p := New()
// 	for _, testCase := range getCaveatTestCases() {
// 		t.Run(testCase.Input, func(t *testing.T) {
// 			if testCase.ExpectFailure {
// 				defer func() {
// 					r := recover()
// 					require.NotNil(t, r)
// 				}()
// 			}

// 			caveat := p.Must().Caveat(testCase.Input)
// 			require.Equal(t, testCase.Expected, caveat)
// 		})
// 	}
// }

func TestIssue84(t *testing.T) {
	rule, err := FromStringRule(`var($a) <- user($a), !($a == "abc")`)
	_ = rule
	require.NoError(t, err)
}

// The FromString helpers share one parser; parsing from many goroutines must be safe.
func TestFromStringConcurrent(t *testing.T) {
	want, err := FromStringFact(`right("/a/file1", "read")`)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				got, err := FromStringFact(`right("/a/file1", "read")`)
				require.NoError(t, err)
				require.Equal(t, want, got)
				_, err = FromStringRule(`head($a) <- body($a), $a == "x"`)
				require.NoError(t, err)
			}
		}()
	}
	wg.Wait()
}

// An unbound parameter inside an expression used to produce a nil term
// instead of an error, and crash later when the element was converted.
func TestUnboundParameterInExpression(t *testing.T) {
	p := New()
	params := ParametersMap{"bound": biscuit.Integer(1)}

	_, err := p.Check(`check if resource($r), $r == {missing}`, params)
	require.ErrorContains(t, err, "unbound parameter: missing")

	_, err = p.Rule(`head($r) <- body($r), $r == {missing}`, params)
	require.ErrorContains(t, err, "unbound parameter: missing")

	_, err = p.Policy(`allow if resource($r), $r == {missing}`, params)
	require.ErrorContains(t, err, "unbound parameter: missing")

	_, err = p.Block(`f(1); check if resource($r), $r == {missing};`, params)
	require.ErrorContains(t, err, "unbound parameter: missing")

	_, err = p.Authorizer(`allow if resource($r), $r == {missing};`, params)
	require.ErrorContains(t, err, "unbound parameter: missing")

	// Bound parameters in expressions still work.
	c, err := p.Check(`check if resource($r), $r == {bound}`, params)
	require.NoError(t, err)
	require.Equal(t, biscuit.Value{Term: biscuit.Integer(1)}, c.Queries[0].Expressions[0][1])
}

// `trusting` clauses on rules, check queries, policies and blocks.
func TestParseScopes(t *testing.T) {
	p := New()
	const keyText = "ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"
	key, err := biscuit.ParsePublicKey(keyText)
	require.NoError(t, err)
	trustKey := biscuit.Scope{Kind: biscuit.ScopePublicKey, PublicKey: key}

	rule, err := p.Rule(`member($u) <- user($u), group($u, "admin") trusting previous, `+keyText, nil)
	require.NoError(t, err)
	require.Equal(t, []biscuit.Scope{{Kind: biscuit.ScopePrevious}, trustKey}, rule.Scopes)

	rule, err = p.Rule(`member($u) <- user($u)`, nil)
	require.NoError(t, err)
	require.Empty(t, rule.Scopes)

	check, err := p.Check(`check if group("admin") trusting `+keyText+` or user("root") trusting authority`, nil)
	require.NoError(t, err)
	require.Len(t, check.Queries, 2)
	require.Equal(t, []biscuit.Scope{trustKey}, check.Queries[0].Scopes)
	require.Equal(t, []biscuit.Scope{{Kind: biscuit.ScopeAuthority}}, check.Queries[1].Scopes)

	policy, err := p.Policy(`allow if query(1, 2) trusting `+keyText, nil)
	require.NoError(t, err)
	require.Equal(t, []biscuit.Scope{trustKey}, policy.Queries[0].Scopes)

	block, err := p.Block(`trusting authority, previous; fact(1); rule($a) <- fact($a) trusting `+keyText+`;`, nil)
	require.NoError(t, err)
	require.Equal(t, []biscuit.Scope{{Kind: biscuit.ScopeAuthority}, {Kind: biscuit.ScopePrevious}}, block.Scopes)
	require.Len(t, block.Facts, 1)
	require.Equal(t, []biscuit.Scope{trustKey}, block.Rules[0].Scopes)

	authorizer, err := p.Authorizer(`trusting `+keyText+`; allow if true;`, nil)
	require.NoError(t, err)
	require.Equal(t, []biscuit.Scope{trustKey}, authorizer.Block.Scopes)

	// A predicate named after a scope keyword is still a predicate.
	fact, err := p.Fact(`previous("x")`, nil)
	require.NoError(t, err)
	require.Equal(t, "previous", fact.Name)

	// The key of a scope is data, as in biscuit-rust: any hexadecimal bytes.
	rule, err = p.Rule(`r($a) <- f($a) trusting ed25519/abcd`, nil)
	require.NoError(t, err)
	require.Equal(t, []byte{0xab, 0xcd}, rule.Scopes[0].PublicKey.Key)
	_, err = p.Rule(`r($a) <- f($a) trusting ed25519/xyz`, nil)
	require.Error(t, err)
	_, err = p.Rule(`r($a) <- f($a) trusting rsa/abcd`, nil)
	require.Error(t, err)
}

// .all() and .any() take a `$param -> body` closure; && and || wrap their
// right side in a closure.
func TestParseClosures(t *testing.T) {
	p := New()

	check, err := p.Check(`check if {1, 2, 3}.all($p -> $p > 0)`, nil)
	require.NoError(t, err)
	require.Equal(t, biscuit.Expression{
		biscuit.Value{Term: biscuit.Set{biscuit.Integer(1), biscuit.Integer(2), biscuit.Integer(3)}},
		biscuit.Closure{Params: []biscuit.Variable{"p"}, Body: biscuit.Expression{
			biscuit.Value{Term: biscuit.Variable("p")},
			biscuit.Value{Term: biscuit.Integer(0)},
			biscuit.BinaryGreaterThan,
		}},
		biscuit.BinaryAll,
	}, check.Queries[0].Expressions[0])

	check, err = p.Check(`check if {1, 2, 3}.any($p -> $p > 1 && {3, 4, 5}.any($q -> $p == $q))`, nil)
	require.NoError(t, err)
	require.Equal(t, biscuit.Expression{
		biscuit.Value{Term: biscuit.Set{biscuit.Integer(1), biscuit.Integer(2), biscuit.Integer(3)}},
		biscuit.Closure{Params: []biscuit.Variable{"p"}, Body: biscuit.Expression{
			biscuit.Value{Term: biscuit.Variable("p")},
			biscuit.Value{Term: biscuit.Integer(1)},
			biscuit.BinaryGreaterThan,
			biscuit.Closure{Body: biscuit.Expression{
				biscuit.Value{Term: biscuit.Set{biscuit.Integer(3), biscuit.Integer(4), biscuit.Integer(5)}},
				biscuit.Closure{Params: []biscuit.Variable{"q"}, Body: biscuit.Expression{
					biscuit.Value{Term: biscuit.Variable("p")},
					biscuit.Value{Term: biscuit.Variable("q")},
					biscuit.BinaryHeterogeneousEqual,
				}},
				biscuit.BinaryAny,
			}},
			biscuit.BinaryLazyAnd,
		}},
		biscuit.BinaryAny,
	}, check.Queries[0].Expressions[0])

	// Extern functions, unary and binary.
	check, err = p.Check(`check if $x.extern::check(), $x.extern::compare("a") == "equal strings"`, nil)
	require.NoError(t, err)
	require.Equal(t, biscuit.Expression{
		biscuit.Value{Term: biscuit.Variable("x")},
		biscuit.ExternUnary{Name: "check"},
	}, check.Queries[0].Expressions[0])
	require.Equal(t, biscuit.Expression{
		biscuit.Value{Term: biscuit.Variable("x")},
		biscuit.Value{Term: biscuit.String("a")},
		biscuit.ExternBinary{Name: "compare"},
		biscuit.Value{Term: biscuit.String("equal strings")},
		biscuit.BinaryHeterogeneousEqual,
	}, check.Queries[0].Expressions[1])
	_, err = p.Check(`check if $x.extern::()`, nil)
	require.Error(t, err)
	_, err = p.Check(`check if $x.unknown()`, nil)
	require.Error(t, err)
	_, err = p.Check(`check if $x.extern::f($p -> $p)`, nil)
	require.ErrorContains(t, err, "does not take a closure")

	// .try_or(): the receiver, with the method calls before it, becomes a
	// closure; the fallback is an ordinary operand.
	check, err = p.Check(`check if ($x === 12).try_or(true), $s.length().try_or(0) > 1`, nil)
	require.NoError(t, err)
	require.Equal(t, biscuit.Expression{
		biscuit.Closure{Body: biscuit.Expression{
			biscuit.Value{Term: biscuit.Variable("x")},
			biscuit.Value{Term: biscuit.Integer(12)},
			biscuit.BinaryEqual,
			biscuit.UnaryParens,
		}},
		biscuit.Value{Term: biscuit.Bool(true)},
		biscuit.BinaryTryOr,
	}, check.Queries[0].Expressions[0])
	require.Equal(t, biscuit.Expression{
		biscuit.Closure{Body: biscuit.Expression{
			biscuit.Value{Term: biscuit.Variable("s")},
			biscuit.UnaryLength,
		}},
		biscuit.Value{Term: biscuit.Integer(0)},
		biscuit.BinaryTryOr,
		biscuit.Value{Term: biscuit.Integer(1)},
		biscuit.BinaryGreaterThan,
	}, check.Queries[0].Expressions[1])
	_, err = p.Check(`check if $x.try_or()`, nil)
	require.ErrorContains(t, err, "fallback")
	_, err = p.Check(`check if $x.try_or($p -> $p)`, nil)
	require.ErrorContains(t, err, "fallback")

	// A method argument that is a plain expression starting with a variable.
	check, err = p.Check(`check if {1, 2}.contains($x)`, nil)
	require.NoError(t, err)
	require.Equal(t, biscuit.Expression{
		biscuit.Value{Term: biscuit.Set{biscuit.Integer(1), biscuit.Integer(2)}},
		biscuit.Value{Term: biscuit.Variable("x")},
		biscuit.BinaryContains,
	}, check.Queries[0].Expressions[0])
}

// Brackets are arrays, braces are sets or maps.
func TestParseArraysAndMaps(t *testing.T) {
	p := New()

	fact, err := p.Fact(`f([1, "a", [2]], {}, [], {"a": 1, 2: "b"}, {1, 2}, {,})`, nil)
	require.NoError(t, err)
	require.Equal(t, []biscuit.Term{
		biscuit.Array{biscuit.Integer(1), biscuit.String("a"), biscuit.Array{biscuit.Integer(2)}},
		biscuit.Map{},
		biscuit.Array{},
		biscuit.Map{{Key: biscuit.String("a"), Value: biscuit.Integer(1)}, {Key: biscuit.Integer(2), Value: biscuit.String("b")}},
		biscuit.Set{biscuit.Integer(1), biscuit.Integer(2)},
		biscuit.Set{},
	}, fact.IDs)

	check, err := p.Check(`check if {"user": {"roles": ["admin"]}}.get("user").get("roles").contains("admin")`, nil)
	require.NoError(t, err)
	require.Equal(t, biscuit.Expression{
		biscuit.Value{Term: biscuit.Map{{Key: biscuit.String("user"), Value: biscuit.Map{{Key: biscuit.String("roles"), Value: biscuit.Array{biscuit.String("admin")}}}}}},
		biscuit.Value{Term: biscuit.String("user")},
		biscuit.BinaryGet,
		biscuit.Value{Term: biscuit.String("roles")},
		biscuit.BinaryGet,
		biscuit.Value{Term: biscuit.String("admin")},
		biscuit.BinaryContains,
	}, check.Queries[0].Expressions[0])

	// A set of one parameter, as the README writes it.
	fact, err = p.Fact(`f({{read}})`, ParametersMap{"read": biscuit.String("read")})
	require.NoError(t, err)
	require.Equal(t, []biscuit.Term{biscuit.Set{biscuit.String("read")}}, fact.IDs)

	_, err = p.Fact(`f({1: "a", 2})`, nil)
	require.ErrorContains(t, err, "map entry without a value")
	_, err = p.Fact(`f({true: 1})`, nil)
	require.ErrorContains(t, err, "map key must be an integer or a string")
	_, err = p.Rule(`r($x) <- s($x), [$x].contains(1)`, nil)
	require.ErrorContains(t, err, "array cannot contain variables")
}
