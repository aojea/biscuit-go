// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
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

// The world prints a set of strings in the order of the symbol table of an
// authorizer snapshot of biscuit-rust, from which the worlds of the
// specification samples come: the policies, then the facts, the rules and
// the checks of the authorizer, then the blocks of the token. This is not
// the order that the authorizer evaluates with.
func TestPrintWorldSnapshotOrder(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	letters := func(name string) Fact {
		return Fact{Predicate{Name: name, IDs: []Term{Set{String("a"), String("b"), String("c"), String("d")}}}}
	}

	builder := NewBuilder(privateRoot)
	require.NoError(t, builder.AddAuthorityFact(Fact{Predicate{Name: "token", IDs: []Term{String("d")}}}))
	require.NoError(t, builder.AddAuthorityFact(letters("in_token")))
	token, err := builder.Build()
	require.NoError(t, err)

	a, err := token.AuthorizerFrom(RootKey(publicRoot))
	require.NoError(t, err)
	a.AddFact(Fact{Predicate{Name: "authorizer", IDs: []Term{String("b")}}})
	a.AddFact(letters("in_authorizer"))
	// allow if "c" == "c"
	a.AddPolicy(Policy{Kind: PolicyKindAllow, Queries: []Rule{{
		Head:        Predicate{Name: "query"},
		Expressions: []Expression{{Value{String("c")}, Value{String("c")}, BinaryHeterogeneousEqual}},
	}}})
	require.NoError(t, a.Authorize())

	// The policy has "c", the authorizer has "b" then "a", the token "d".
	world := a.PrintWorld()
	require.Contains(t, world, `in_token({"c", "b", "a", "d"})`)
	require.Contains(t, world, `in_authorizer({"c", "b", "a", "d"})`)
	// The authorizer evaluates with the token first: "d", "a", "b", "c".
	require.Equal(t, datalog.SymbolTable{"token", "d", "in_token", "a", "b", "c", "authorizer", "in_authorizer"}, *a.(*authorizer).symbols)
}

// The world prints the rules of the authorizer as soon as they are added,
// as it does for its facts: before the world is run, and for a rule that
// is added after a run. Each rule is printed one time.
func TestPrintWorldRulesBeforeRun(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	token, err := NewBuilder(privateRoot).Build()
	require.NoError(t, err)
	rule := func(name string) Rule {
		return Rule{
			Head: Predicate{Name: name, IDs: []Term{Variable("r")}},
			Body: []Predicate{{Name: "resource", IDs: []Term{Variable("r")}}},
		}
	}

	a, err := token.AuthorizerFrom(RootKey(publicRoot))
	require.NoError(t, err)
	a.AddFact(Fact{Predicate{Name: "resource", IDs: []Term{String("file1")}}})
	a.AddRule(rule("first"))
	a.AddPolicy(DefaultAllowPolicy)
	require.Equal(t, 1, strings.Count(a.PrintWorld(), "first($r) <- resource($r);"))

	require.NoError(t, a.Authorize())
	a.AddRule(rule("second"))
	world := a.PrintWorld()
	require.Equal(t, 1, strings.Count(world, "first($r) <- resource($r);"))
	require.Equal(t, 1, strings.Count(world, "second($r) <- resource($r);"))
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

// The checks and the policies share the time limit of the rules
// (WithMaxDuration), as in biscuit-rust. A check or a policy with a join
// that is too long stops with the timeout of the run limits, which is not
// an execution error: in the authorizer, in the authority block and in a
// block that is appended to the token.
func TestAuthorizeTimeLimitOnChecksAndPolicies(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	// a($x), b($x), c($x) has no match: the join reads each combination of
	// the facts, which takes much more time than the default limit.
	const n = 60
	names := []string{"a", "b", "c"}
	join := Rule{Head: Predicate{Name: "query"}}
	for _, name := range names {
		join.Body = append(join.Body, Predicate{Name: name, IDs: []Term{Variable("x")}})
	}
	check := Check{Queries: []Rule{join}}
	newBuilder := func() Builder {
		builder := NewBuilder(privateRoot)
		for i, name := range names {
			for j := range n {
				require.NoError(t, builder.AddAuthorityFact(Fact{Predicate{Name: name, IDs: []Term{Integer(i*n + j)}}}))
			}
		}
		return builder
	}
	token, err := newBuilder().Build()
	require.NoError(t, err)
	builder := newBuilder()
	require.NoError(t, builder.AddAuthorityCheck(check))
	withAuthorityCheck, err := builder.Build()
	require.NoError(t, err)
	block := token.CreateBlock()
	require.NoError(t, block.AddCheck(check))
	withBlockCheck, err := token.Append(rand.Reader, block.Build())
	require.NoError(t, err)

	for name, testCase := range map[string]struct {
		token *Biscuit
		add   func(Authorizer)
	}{
		"authorizer check": {token, func(a Authorizer) { a.AddCheck(check) }},
		"authority check":  {withAuthorityCheck, func(Authorizer) {}},
		"block check":      {withBlockCheck, func(Authorizer) {}},
		"policy":           {token, func(a Authorizer) { a.AddPolicy(Policy{Kind: PolicyKindDeny, Queries: check.Queries}) }},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := testCase.token.AuthorizerFrom(RootKey(publicRoot))
			require.NoError(t, err)
			testCase.add(a)
			a.AddPolicy(DefaultAllowPolicy)
			err = a.Authorize()
			require.ErrorIs(t, err, datalog.ErrWorldRunLimitTimeout)
			require.NotErrorIs(t, err, ErrExecution)
		})
	}
}

// biscuit-rust gives the symbols of the facts of the authorizer before those
// of its rules, also when a rule is added first. The order of the symbols
// is the order in which a check reads facts that have strings.
func TestAuthorizerRuleSymbolsAfterFacts(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	token, err := NewBuilder(privateRoot).Build()
	require.NoError(t, err)

	// seen($s) <- other($s), $s != "x"
	rule := Rule{
		Head:        Predicate{Name: "seen", IDs: []Term{Variable("s")}},
		Body:        []Predicate{{Name: "other", IDs: []Term{Variable("s")}}},
		Expressions: []Expression{{Value{Variable("s")}, Value{String("x")}, BinaryNotEqual}},
	}
	// check if f($s, $t), 10 / $t > 4
	check := Check{Queries: []Rule{{
		Head: Predicate{Name: "query"},
		Body: []Predicate{{Name: "f", IDs: []Term{Variable("s"), Variable("t")}}},
		Expressions: []Expression{{
			Value{Integer(10)}, Value{Variable("t")}, BinaryDiv, Value{Integer(4)}, BinaryGreaterThan,
		}},
	}}}
	authorize := func(save bool, facts ...Fact) error {
		a, err := token.AuthorizerFrom(RootKey(publicRoot))
		require.NoError(t, err)
		a.AddRule(rule)
		a.AddCheck(check)
		a.AddPolicy(DefaultAllowPolicy)
		if save {
			_, err := a.SerializePolicies()
			require.NoError(t, err)
		}
		for _, fact := range facts {
			a.AddFact(fact)
		}
		return a.Authorize()
	}
	x := Fact{Predicate{Name: "f", IDs: []Term{String("x"), Integer(1)}}}
	y := Fact{Predicate{Name: "f", IDs: []Term{String("y"), Integer(0)}}}

	// "y" is the first string of the facts: f("y", 0) is read first, also
	// with "x" in a rule that was added before, and also when the policies
	// are saved before the facts are added.
	require.ErrorIs(t, authorize(false, y, x), datalog.ErrExprDivByZero)
	require.ErrorIs(t, authorize(true, y, x), datalog.ErrExprDivByZero)
	// "x" is the first string: f("x", 1) is read first, and it matches.
	require.NoError(t, authorize(false, x, y))
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
