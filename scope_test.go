// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/internal/crypto"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPublicKeyParse(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, err := PublicKeyFrom(pub)
	require.NoError(t, err)
	parsed, err := ParsePublicKey(key.String())
	require.NoError(t, err)
	require.Equal(t, key, parsed)

	// A scope holds its key as data, as in biscuit-rust: the bytes do not
	// have to be a key of the algorithm.
	short, err := ParsePublicKey("ed25519/abcd")
	require.NoError(t, err)
	require.Equal(t, PublicKey{Algorithm: datalog.AlgorithmEd25519, Key: []byte{0xab, 0xcd}}, short)
	_, err = ParsePublicKey("ed25519/xyz")
	require.ErrorContains(t, err, "invalid public key")
	_, err = ParsePublicKey("nokey")
	require.ErrorContains(t, err, "expected algorithm/hex")
}

// A block of biscuit-rust can carry a scope key that is not a key of its
// algorithm: the block is read, and the key is the key of no block.
func TestScopeKeyIsData(t *testing.T) {
	_, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	key, err := ParsePublicKey("secp256r1/0102")
	require.NoError(t, err)

	builder := NewBuilder(privateRoot)
	require.NoError(t, builder.AddAuthorityCheck(Check{Queries: []Rule{{
		Head:   Predicate{Name: "query"},
		Body:   []Predicate{{Name: "group", IDs: []Term{String("admin")}}},
		Scopes: []Scope{{Kind: ScopePublicKey, PublicKey: key}},
	}}}))
	token, err := builder.Build()
	require.NoError(t, err)

	deser, err := Unmarshal(mustSerialize(t, token))
	require.NoError(t, err)
	require.Equal(t, publicKeyTable{key}, deser.publicKeys)
	require.Contains(t, deser.String(), "trusting secp256r1/0102")

	// An algorithm that the schema does not define is not data: biscuit-rust
	// reads it as Ed25519, and the key would be equal to another key.
	for _, algorithm := range []pb.PublicKey_Algorithm{2, 100, -1} {
		_, err = protoBlockToTokenBlock(&pb.Block{
			Version:    proto.Uint32(4),
			PublicKeys: []*pb.PublicKey{{Algorithm: algorithm.Enum(), Key: []byte{1, 2}}},
		}, nil)
		require.ErrorIs(t, err, crypto.ErrUnsupportedAlgorithm, "algorithm %d", algorithm)
	}
}

// Scopes round-trip through the token: keys are interned once per token and
// blocks carry only the keys they introduce; blocks with scopes are v4.
func TestScopesRoundTrip(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	trust1, err := TrustingPublicKey(pub1)
	require.NoError(t, err)
	trust2, err := TrustingPublicKey(pub2)
	require.NoError(t, err)

	builder := NewBuilder(privateRoot)
	require.NoError(t, builder.AddAuthorityCheck(Check{Queries: []Rule{{
		Head:   Predicate{Name: "query"},
		Body:   []Predicate{{Name: "group", IDs: []Term{String("admin")}}},
		Scopes: []Scope{{Kind: ScopePrevious}, trust1},
	}}}))
	b1, err := builder.Build()
	require.NoError(t, err)
	require.EqualValues(t, 4, b1.authority.version)
	require.Equal(t, []datalog.PublicKey{trust1.PublicKey}, b1.authority.publicKeys)

	block := b1.CreateBlock()
	block.AddScope(Scope{Kind: ScopeAuthority})
	require.NoError(t, block.AddRule(Rule{
		Head:   Predicate{Name: "allowed", IDs: []Term{Variable("u")}},
		Body:   []Predicate{{Name: "user", IDs: []Term{Variable("u")}}},
		Scopes: []Scope{trust1, trust2},
	}))
	b2, err := b1.Append(rand.Reader, block.Build())
	require.NoError(t, err)
	// trust1 is already in the token's table, only trust2 is new.
	require.Equal(t, []datalog.PublicKey{trust2.PublicKey}, b2.blocks[0].publicKeys)

	deser, err := Unmarshal(mustSerialize(t, b2))
	require.NoError(t, err)
	require.Equal(t, publicKeyTable{trust1.PublicKey, trust2.PublicKey}, deser.publicKeys)
	require.Equal(t, []Scope{{Kind: ScopeAuthority}}, deser.blocks[0].scopes)
	require.Equal(t, []Scope{trust1, trust2}, deser.blocks[0].rules[0].Scopes)
	require.Equal(t, []Scope{{Kind: ScopePrevious}, trust1}, deser.authority.checks[0].Queries[0].Scopes)
	require.Contains(t, deser.String(), "trusting previous, "+trust1.PublicKey.String())
	require.Contains(t, deser.Code()[0], "trusting authority;")

	_, err = deser.AuthorizerFrom(RootKey(publicRoot))
	require.NoError(t, err)
}

// The scopes of a parsed block go to the block it is added to, for the
// authority block as for the others.
func TestAddBlockKeepsScopes(t *testing.T) {
	_, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	trust, err := TrustingPublicKey(pub)
	require.NoError(t, err)
	parsed := ParsedBlock{
		Facts:  []Fact{{Predicate{Name: "right", IDs: []Term{String("read")}}}},
		Scopes: []Scope{trust},
	}

	builder := NewBuilder(privateRoot)
	require.NoError(t, builder.AddBlock(parsed))
	token, err := builder.Build()
	require.NoError(t, err)
	require.Equal(t, []Scope{trust}, token.authority.scopes)
	require.EqualValues(t, 4, token.authority.version)

	block := token.CreateBlock()
	require.NoError(t, block.AddBlock(ParsedBlock{Scopes: []Scope{{Kind: ScopePrevious}}}))
	token, err = token.Append(rand.Reader, block.Build())
	require.NoError(t, err)

	deser, err := Unmarshal(mustSerialize(t, token))
	require.NoError(t, err)
	require.Equal(t, []Scope{trust}, deser.authority.scopes)
	require.Equal(t, []Scope{{Kind: ScopePrevious}}, deser.blocks[0].scopes)
}

// A block declares only the keys the token does not have yet. Skipping a
// repeated key would number the keys after it differently from the other
// implementations, so the block is refused instead.
func TestPublicKeyTableOverlap(t *testing.T) {
	_, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	trust, err := TrustingPublicKey(pub)
	require.NoError(t, err)
	trusting := Check{Queries: []Rule{{
		Head:   Predicate{Name: "query"},
		Body:   []Predicate{{Name: "group", IDs: []Term{String("admin")}}},
		Scopes: []Scope{trust},
	}}}

	b0, err := NewBuilder(privateRoot).Build()
	require.NoError(t, err)

	// Both blocks are built from b0, which does not know the key: each declares it.
	first, stale := b0.CreateBlock(), b0.CreateBlock()
	require.NoError(t, first.AddCheck(trusting))
	require.NoError(t, stale.AddCheck(trusting))

	b1, err := b0.Append(rand.Reader, first.Build())
	require.NoError(t, err)
	require.Equal(t, publicKeyTable{trust.PublicKey}, b1.publicKeys)

	_, err = b1.Append(rand.Reader, stale.Build())
	require.ErrorIs(t, err, ErrPublicKeyTableOverlap)

	// The same shapes in a serialized token; Unmarshal does not verify signatures.
	for _, tc := range []struct {
		name   string
		tamper func(*pb.Biscuit)
	}{
		{
			name: "key declared twice by a block",
			tamper: func(c *pb.Biscuit) {
				editSignedBlock(t, c.Blocks[0], func(b *pb.Block) { b.PublicKeys = append(b.PublicKeys, b.PublicKeys[0]) })
			},
		},
		{
			name: "key declared by an earlier block",
			tamper: func(c *pb.Biscuit) {
				editSignedBlock(t, c.Authority, func(b *pb.Block) { b.PublicKeys = []*pb.PublicKey{tokenPublicKeyToProtoPublicKey(trust.PublicKey)} })
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			container := proto.Clone(b1.container).(*pb.Biscuit)
			tc.tamper(container)
			serialized, err := proto.Marshal(container)
			require.NoError(t, err)

			_, err = Unmarshal(serialized)
			require.ErrorIs(t, err, ErrPublicKeyTableOverlap)
		})
	}
}

// editSignedBlock rewrites the serialized content of a signed block, leaving
// its signature as it was.
func editSignedBlock(t *testing.T, sb *pb.SignedBlock, edit func(*pb.Block)) {
	t.Helper()
	block := new(pb.Block)
	require.NoError(t, proto.Unmarshal(sb.Block, block))
	edit(block)
	edited, err := proto.Marshal(block)
	require.NoError(t, err)
	sb.Block = edited
}

// A block's rules and checks read the authority block, the authorizer and
// their own block unless a scope says otherwise.
func TestScopesAuthorization(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)

	b1, err := NewBuilder(privateRoot).Build()
	require.NoError(t, err)

	block1 := b1.CreateBlock()
	require.NoError(t, block1.AddFact(Fact{Predicate{Name: "block1", IDs: []Term{Integer(1)}}}))
	b2, err := b1.Append(rand.Reader, block1.Build())
	require.NoError(t, err)

	authorize := func(t *testing.T, check Check) error {
		t.Helper()
		block2 := b2.CreateBlock()
		require.NoError(t, block2.AddCheck(check))
		b3, err := b2.Append(rand.Reader, block2.Build())
		require.NoError(t, err)
		ab, err := b3.AuthorizerFrom(RootKey(publicRoot))
		require.NoError(t, err)
		ab.AddPolicy(DefaultAllowPolicy)
		return ab.Authorize()
	}

	query := Rule{Head: Predicate{Name: "query"}, Body: []Predicate{{Name: "block1", IDs: []Term{Variable("x")}}}}

	// Block 1 is not visible from block 2 by default.
	require.ErrorContains(t, authorize(t, Check{Queries: []Rule{query}}), "failed to verify block #2 check #0")

	// `trusting previous` makes it visible.
	previous := query
	previous.Scopes = []Scope{{Kind: ScopePrevious}}
	require.NoError(t, authorize(t, Check{Queries: []Rule{previous}}))

	// `trusting authority` alone does not.
	authority := query
	authority.Scopes = []Scope{{Kind: ScopeAuthority}}
	require.ErrorContains(t, authorize(t, Check{Queries: []Rule{authority}}), "failed to verify block #2 check #0")

	// Neither does trusting a key no block was signed with.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	trust, err := TrustingPublicKey(pub)
	require.NoError(t, err)
	keyed := query
	keyed.Scopes = []Scope{trust}
	require.ErrorContains(t, authorize(t, Check{Queries: []Rule{keyed}}), "failed to verify block #2 check #0")

	// On the authorizer side `previous` designates no block, as in the
	// reference implementation: later blocks are reached through the key of
	// a third-party block only.
	for _, q := range []Rule{query, previous} {
		ab, err := b2.AuthorizerFrom(RootKey(publicRoot))
		require.NoError(t, err)
		ab.AddPolicy(Policy{Kind: PolicyKindAllow, Queries: []Rule{q}})
		require.ErrorIs(t, ab.Authorize(), ErrNoMatchingPolicy)
	}
}
