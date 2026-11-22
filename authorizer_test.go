// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/stretchr/testify/require"
)

func TestAuthorizerAppliesOptions(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)

	builder := NewBuilder(privateRoot)
	if err := builder.AddAuthorityFact(Fact{Predicate{Name: "right", IDs: []Term{String("read")}}}); err != nil {
		t.Fatal(err)
	}
	b, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	// The limits apply when the rules generate facts: with a limit of one
	// fact, the fact that this rule adds is one too many, so Authorize only
	// fails if the option reached the authorizer's world.
	v, err := b.Authorizer(publicRoot, WithWorldOptions(datalog.WithMaxFacts(1)))
	if err != nil {
		t.Fatal(err)
	}
	v.AddRule(Rule{
		Head: Predicate{Name: "can", IDs: []Term{Variable("op")}},
		Body: []Predicate{{Name: "right", IDs: []Term{Variable("op")}}},
	})
	v.AddPolicy(DefaultAllowPolicy)
	if err := v.Authorize(); !errors.Is(err, datalog.ErrWorldRunLimitMaxFacts) {
		t.Fatalf("Authorize() = %v, want %v", err, datalog.ErrWorldRunLimitMaxFacts)
	}
}

// The strings of the token get their symbols in the table of the authorizer
// before the strings of the authorizer, as in biscuit-rust: the facts, the
// rules, then the checks of each block. A set of strings has the order of
// the symbols, so this order decides the element that .any() sees first.
func TestAuthorizerGivesTokenSymbolsFirst(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)

	builder := NewBuilder(privateRoot)
	require.NoError(t, builder.AddAuthorityFact(Fact{Predicate{Name: "token", IDs: []Term{String("b")}}}))
	// check if token($x), $x != "c"
	require.NoError(t, builder.AddAuthorityCheck(Check{Queries: []Rule{{
		Head:        Predicate{Name: "query"},
		Body:        []Predicate{{Name: "token", IDs: []Term{Variable("x")}}},
		Expressions: []Expression{{Value{Variable("x")}, Value{String("c")}, BinaryHeterogeneousNotEqual}},
	}}}))
	token, err := builder.Build()
	require.NoError(t, err)

	a, err := token.AuthorizerFrom(RootKey(publicRoot))
	require.NoError(t, err)
	a.AddFact(Fact{Predicate{Name: "letters", IDs: []Term{Set{String("a"), String("b"), String("c")}}}})
	a.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, a.Authorize())
	require.Equal(t, datalog.SymbolTable{"token", "b", "x", "c", "letters", "a", "allow"}, *a.(*authorizer).symbols)

	// check if {"a", "b"}.any($p -> $p == "a" || 1 / 0 == 1): "b" comes
	// first, and the division fails before "a" is seen.
	a, err = token.AuthorizerFrom(RootKey(publicRoot))
	require.NoError(t, err)
	a.AddCheck(Check{Queries: []Rule{{
		Head: Predicate{Name: "query"},
		Expressions: []Expression{{
			Value{Set{String("a"), String("b")}},
			Closure{Params: []Variable{"p"}, Body: Expression{
				Value{Variable("p")}, Value{String("a")}, BinaryHeterogeneousEqual,
				Closure{Body: Expression{Value{Integer(1)}, Value{Integer(0)}, BinaryDiv, Value{Integer(1)}, BinaryHeterogeneousEqual}},
				BinaryLazyOr,
			}},
			BinaryAny,
		}},
	}}})
	a.AddPolicy(DefaultAllowPolicy)
	require.ErrorIs(t, a.Authorize(), datalog.ErrExprDivByZero)
}

func TestVerifierDefaultPolicy(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot)
	err := builder.AddAuthorityFact(Fact{Predicate{
		Name: "right",
		IDs: []Term{
			String("/a/file1.txt"),
			String("read"),
		},
	}})
	require.NoError(t, err)

	b, err := builder.Build()
	require.NoError(t, err)

	v, err := b.Authorizer(publicRoot)
	require.NoError(t, err)

	v.AddPolicy(DefaultDenyPolicy)
	err = v.Authorize()
	require.Equal(t, err, ErrPolicyDenied)

	v.Reset()
	v.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, v.Authorize())
}

// An authorizer that is used again runs the rules of the token one time, and
// Reset removes the rules that were added for the run before it.
func TestAuthorizerReuse(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)

	variable := Variable("x")
	rule := func(head, body string) Rule {
		return Rule{
			Head: Predicate{Name: head, IDs: []Term{variable}},
			Body: []Predicate{{Name: body, IDs: []Term{variable}}},
		}
	}
	builder := NewBuilder(privateRoot)
	require.NoError(t, builder.AddAuthorityFact(Fact{Predicate{Name: "value", IDs: []Term{Integer(1)}}}))
	require.NoError(t, builder.AddAuthorityRule(rule("token_rule", "value")))
	b, err := builder.Build()
	require.NoError(t, err)

	v, err := b.AuthorizerFrom(RootKey(publicRoot))
	require.NoError(t, err)
	rules := func() []string {
		var res []string
		for _, r := range v.(*authorizer).world.Rules() {
			res = append(res, r.Rule.Head.Name.String())
		}
		return res
	}
	name := func(s string) string {
		return v.(*authorizer).symbols.Sym(s).String()
	}

	v.AddRule(rule("first_run", "value"))
	v.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, v.Authorize())
	require.ElementsMatch(t, []string{name("first_run"), name("token_rule")}, rules())

	// A second call does not add the rules again.
	require.NoError(t, v.Authorize())
	require.ElementsMatch(t, []string{name("first_run"), name("token_rule")}, rules())

	v.Reset()
	require.Empty(t, rules())
	v.AddRule(rule("second_run", "value"))
	v.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, v.Authorize())
	require.ElementsMatch(t, []string{name("second_run"), name("token_rule")}, rules())
}

// Query runs on the same content as Authorize: it reads the facts and the
// rules of the token before Authorize is called, as in biscuit-rust, and
// the rules of the token apply to a fact that is added after Authorize.
func TestAuthorizerQueryLoadsToken(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)

	// resource("file1"); right($f) <- resource($f);
	builder := NewBuilder(privateRoot)
	require.NoError(t, builder.AddAuthorityFact(Fact{Predicate{Name: "resource", IDs: []Term{String("file1")}}}))
	require.NoError(t, builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Term{Variable("f")}},
		Body: []Predicate{{Name: "resource", IDs: []Term{Variable("f")}}},
	}))
	token, err := builder.Build()
	require.NoError(t, err)

	rights := func(a Authorizer) []Term {
		facts, err := a.Query(Rule{
			Head: Predicate{Name: "query", IDs: []Term{Variable("f")}},
			Body: []Predicate{{Name: "right", IDs: []Term{Variable("f")}}},
		})
		require.NoError(t, err)
		var res []Term
		for _, f := range facts {
			res = append(res, f.IDs...)
		}
		return res
	}

	a, err := token.AuthorizerFrom(RootKey(publicRoot))
	require.NoError(t, err)
	require.ElementsMatch(t, []Term{String("file1")}, rights(a))

	a.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, a.Authorize())
	a.AddFact(Fact{Predicate{Name: "resource", IDs: []Term{String("file2")}}})
	require.ElementsMatch(t, []Term{String("file1"), String("file2")}, rights(a))
}

func TestVerifierPolicies(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot)
	err := builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Term{Variable("file"), Variable("operation")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Variable("file")}},
			{Name: "operation", IDs: []Term{Variable("operation")}},
		},
	})
	require.NoError(t, err)

	b, err := builder.Build()
	require.NoError(t, err)

	v, err := b.Authorizer(publicRoot)
	require.NoError(t, err)

	policy := Policy{Kind: PolicyKindAllow, Queries: []Rule{
		{
			Head: Predicate{Name: "allow_read"},
			Body: []Predicate{
				{Name: "right", IDs: []Term{Variable("file"), Variable("operation")}},
			},
			Expressions: []Expression{
				{
					Value{Term: Variable("operation")},
					Value{Term: String("read")},
					BinaryEqual,
				},
			},
		},
	}}

	v.AddPolicy(policy)
	v.AddFact(Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{String("read")},
	}})
	v.AddFact(Fact{Predicate: Predicate{
		Name: "resource",
		IDs:  []Term{String("some_file.txt")},
	}})

	require.NoError(t, v.Authorize())

	v, err = b.Authorizer(publicRoot)
	require.NoError(t, err)
	v.AddPolicy(policy)
	v.AddFact(Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{String("write")},
	}})
	v.AddFact(Fact{Predicate: Predicate{
		Name: "resource",
		IDs:  []Term{String("some_file.txt")},
	}})
	require.Equal(t, v.Authorize(), ErrNoMatchingPolicy)
}

func TestVerifierSerializeLoad(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot)
	b, err := builder.Build()
	require.NoError(t, err)

	v1, err := b.Authorizer(publicRoot)
	require.NoError(t, err)

	policy := Policy{Kind: PolicyKindAllow, Queries: []Rule{
		{
			Head: Predicate{Name: "allow_read", IDs: []Term{Variable("file"), Variable("operation")}},
			Body: []Predicate{
				{Name: "right", IDs: []Term{Variable("file"), Variable("operation")}},
			},
			Expressions: []Expression{
				{
					Value{Term: Variable("operation")},
					Value{Term: String("read")},
					BinaryEqual,
				},
			},
		},
	}}

	fact1 := Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{String("read")},
	}}
	fact2 := Fact{Predicate: Predicate{
		Name: "resource",
		IDs:  []Term{String("some_file.txt")},
	}}
	rule1 := Rule{
		Head: Predicate{Name: "rule1", IDs: []Term{Variable("test")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{String("some_file.txt")}},
		},
		Expressions: []Expression{
			{Value{Term: Integer(1)}, Value{Term: Integer(2)}, BinaryLessThan},
		},
	}
	check1 := Check{Queries: []Rule{rule1}}

	v1.AddFact(fact1)
	v1.AddFact(fact2)
	v1.AddRule(rule1)
	v1.AddCheck(check1)
	v1.AddPolicy(policy)
	s, err := v1.SerializePolicies()
	require.NoError(t, err)

	v2, err := b.Authorizer(publicRoot)
	require.NoError(t, err)

	require.NoError(t, v2.LoadPolicies(s))

	require.Equal(t, v1.(*authorizer).world.Facts(), v2.(*authorizer).world.Facts())
	// Rules stay with the authorizer until the world is run.
	require.Len(t, v1.(*authorizer).rules, 1)
	require.Equal(t, v1.(*authorizer).rules, v2.(*authorizer).rules)
	require.Equal(t, v1.(*authorizer).checks, v2.(*authorizer).checks)
	require.Equal(t, v1.(*authorizer).policies, v2.(*authorizer).policies)
}

// The saved policies have their own symbol table. LoadPolicies translates
// them to the table of the authorizer: the strings of the token, and of a
// fact that the authorizer has before the load, stay what they are.
func TestLoadPoliciesKeepsSymbols(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	fact := func(name, value string) Fact {
		return Fact{Predicate{Name: name, IDs: []Term{String(value)}}}
	}
	authorizer := func(name string) Authorizer {
		builder := NewBuilder(privateRoot)
		require.NoError(t, builder.AddAuthorityFact(fact(name, name+"_value")))
		token, err := builder.Build()
		require.NoError(t, err)
		a, err := token.AuthorizerFrom(RootKey(publicRoot))
		require.NoError(t, err)
		return a
	}

	saver := authorizer("first")
	saver.AddFact(fact("resource", "file1"))
	saver.AddCheck(Check{Queries: []Rule{{
		Head: Predicate{Name: "query"},
		Body: []Predicate{{Name: "resource", IDs: []Term{String("file1")}}},
	}}})
	saver.AddPolicy(DefaultAllowPolicy)
	saved, err := saver.SerializePolicies()
	require.NoError(t, err)

	loader := authorizer("second")
	loader.AddFact(fact("before", "load"))
	require.NoError(t, loader.LoadPolicies(saved))
	require.NoError(t, loader.Authorize())
	world := loader.PrintWorld()
	for _, want := range []string{`second("second_value")`, `before("load")`, `resource("file1")`} {
		require.Contains(t, world, want)
	}
}
