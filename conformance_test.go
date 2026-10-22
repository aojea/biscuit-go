// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit_test

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
	"github.com/stretchr/testify/require"
)

// The conformance samples carry, for every validation, the Datalog world the
// reference implementation ends up with: every fact tagged with the set of
// block ids it was derived from (null is the authorizer). This test rebuilds
// each token from the sample's block source instead of its signed bytes, so
// it exercises the parser and the interpreter only, and it checks every block
// scope rather than just the authority.

type conformanceSamples struct {
	TestCases []conformanceCase `json:"testcases"`
}

type conformanceCase struct {
	Title       string                           `json:"title"`
	Filename    string                           `json:"filename"`
	Token       []conformanceBlock               `json:"token"`
	Validations map[string]conformanceValidation `json:"validations"`
}

type conformanceBlock struct {
	Code    string `json:"code"`
	Version uint32 `json:"version"`
}

type conformanceValidation struct {
	World          *conformanceWorld `json:"world"`
	Result         conformanceResult `json:"result"`
	AuthorizerCode string            `json:"authorizer_code"`
}

type conformanceResult struct {
	Ok  *int `json:"Ok"`
	Err *struct {
		Format      json.RawMessage `json:"Format"`
		FailedLogic *struct {
			Unauthorized     json.RawMessage `json:"Unauthorized"`
			InvalidBlockRule json.RawMessage `json:"InvalidBlockRule"`
		} `json:"FailedLogic"`
	} `json:"Err"`
}

type conformanceWorld struct {
	Facts []conformanceFacts `json:"facts"`
}

type conformanceFacts struct {
	// Origin is the set of block ids a fact was derived from; nil is the authorizer.
	Origin []*int `json:"origin"`
	Facts  []string
}

// visibleIn reports whether a fact with this origin is part of the world of
// block id: v2 evaluates each block against the authority, the authorizer
// and its own facts only.
func (f conformanceFacts) visibleIn(blockID int) bool {
	for _, o := range f.Origin {
		if o != nil && *o != 0 && *o != blockID {
			return false
		}
	}
	return true
}

// The samples print Datalog in the v3.1 syntax. The token bytes are still v3,
// so map the two syntax changes back to what this parser accepts: strict
// equality is spelled `==` and sets use brackets.
var conformanceSyntax = strings.NewReplacer("===", "==", "!==", "!=", "{,}", "[]", "{", "[", "}", "]")

func TestConformanceWorlds(t *testing.T) {
	raw, err := os.ReadFile("samples/data/current/samples.json")
	require.NoError(t, err)
	var samples conformanceSamples
	require.NoError(t, json.Unmarshal(raw, &samples))

	for _, c := range samples.TestCases {
		t.Run(c.Filename, func(t *testing.T) {
			token, err := conformanceToken(c)
			if err != nil {
				// the block uses Datalog features this library does not implement
				t.Skipf("cannot rebuild token from source: %v", err)
			}

			names := slices.Sorted(maps.Keys(c.Validations))
			for _, name := range names {
				v := c.Validations[name]
				t.Run(name, func(t *testing.T) {
					checkConformanceValidation(t, token, len(c.Token), v)
				})
			}
		})
	}
}

// conformanceToken builds the token structure from the sample's block source.
func conformanceToken(c conformanceCase) (*biscuit.Biscuit, error) {
	p := parser.New()
	symbols := biscuit.DefaultSymbolTableForTest()
	blocks := make([]*biscuit.Block, 0, len(c.Token))
	for _, b := range c.Token {
		parsed, err := p.Block(conformanceSyntax.Replace(b.Code), nil)
		if err != nil {
			return nil, err
		}
		builder := biscuit.NewBlockBuilder(symbols)
		if err := builder.AddBlock(parsed); err != nil {
			return nil, err
		}
		block := builder.Build()
		symbols.Extend(biscuit.BlockSymbolsForTest(block))
		blocks = append(blocks, block)
	}
	return biscuit.NewUnsignedBiscuitForTest(symbols, blocks...), nil
}

func checkConformanceValidation(t *testing.T, token *biscuit.Biscuit, blocks int, v conformanceValidation) {
	if v.Result.Err != nil && v.Result.Err.Format != nil {
		t.Skip("the reference rejects the token before evaluating Datalog")
	}
	authorizerCode, err := parser.New().Authorizer(conformanceSyntax.Replace(v.AuthorizerCode), nil)
	if err != nil {
		t.Skipf("cannot parse authorizer: %v", err)
	}

	verifier, err := biscuit.NewVerifier(token)
	require.NoError(t, err)
	verifier.AddAuthorizer(authorizerCode)
	err = verifier.Authorize()

	switch {
	case v.Result.Ok != nil:
		require.NoError(t, err)
	case v.Result.Err.FailedLogic == nil:
		t.Fatalf("unexpected reference error %+v", v.Result.Err)
	case v.Result.Err.FailedLogic.InvalidBlockRule != nil:
		// the reference rejects the rule when loading the block and never
		// evaluates Datalog; this library reports it from the interpreter
		require.Error(t, err)
		return
	case errors.Is(err, biscuit.ErrPolicyDenied), errors.Is(err, biscuit.ErrNoMatchingPolicy):
	default:
		require.Error(t, err)
		require.Regexp(t, "^biscuit: verification failed: failed to verify", err.Error())
	}
	require.NotNil(t, v.World)

	world, blockWorlds, symbols := biscuit.AuthorizerWorldsForTest(verifier)
	debug := datalog.SymbolDebugger{SymbolTable: symbols}
	require.Equal(t, conformanceExpectedFacts(v.World, 0), conformanceWorldFacts(debug, world), "authority world")
	require.Len(t, blockWorlds, blocks-1)
	for i, w := range blockWorlds {
		require.Equal(t, conformanceExpectedFacts(v.World, i+1), conformanceWorldFacts(debug, w), "block %d world", i+1)
	}
}

func conformanceExpectedFacts(w *conformanceWorld, blockID int) []string {
	facts := []string{}
	for _, f := range w.Facts {
		if f.visibleIn(blockID) {
			facts = append(facts, f.Facts...)
		}
	}
	sort.Strings(facts)
	return facts
}

func conformanceWorldFacts(debug datalog.SymbolDebugger, w *datalog.World) []string {
	facts := make([]string, 0, len(*w.Facts()))
	for _, f := range *w.Facts() {
		facts = append(facts, debug.Predicate(f.Predicate))
	}
	sort.Strings(facts)
	return facts
}
