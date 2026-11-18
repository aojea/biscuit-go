// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// The flow of the spec: the holder issues a request, the third party signs a
// block for it, the holder appends it; rules see its facts only when they
// trust the third party's key.
func TestThirdPartyBlock(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	for _, tc := range []struct {
		name    string
		private stdcrypto.Signer
		public  stdcrypto.PublicKey
	}{
		{"ed25519", edPriv, edPub},
		{"secp256r1", ecKey, &ecKey.PublicKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
			thirdPartyPublic := tc.public
			trust, err := TrustingPublicKey(thirdPartyPublic)
			require.NoError(t, err)

			// The authority block requires a fact from the third party.
			builder := NewBuilder(privateRoot)
			require.NoError(t, builder.AddAuthorityFact(Fact{Predicate{Name: "right", IDs: []Term{String("read")}}}))
			require.NoError(t, builder.AddAuthorityCheck(Check{Queries: []Rule{{
				Head:   Predicate{Name: "query"},
				Body:   []Predicate{{Name: "group", IDs: []Term{String("admin")}}},
				Scopes: []Scope{trust},
			}}}))
			token, err := builder.Build()
			require.NoError(t, err)

			// Holder side: the request travels serialized.
			request, err := token.ThirdPartyRequest()
			require.NoError(t, err)
			requestBytes, err := request.Serialize()
			require.NoError(t, err)

			// Third party side: a block with its own symbols, signed with its key.
			request, err = UnmarshalThirdPartyBlockRequest(requestBytes)
			require.NoError(t, err)
			blockBuilder := NewThirdPartyBlockBuilder()
			require.NoError(t, blockBuilder.AddFact(Fact{Predicate{Name: "group", IDs: []Term{String("admin")}}}))
			require.NoError(t, blockBuilder.AddCheck(Check{Queries: []Rule{{
				Head: Predicate{Name: "query"},
				Body: []Predicate{{Name: "right", IDs: []Term{String("read")}}},
			}}}))
			contents, err := request.CreateBlock(tc.private, blockBuilder)
			require.NoError(t, err)
			contentsBytes, err := contents.Serialize()
			require.NoError(t, err)

			// Holder side again.
			contents, err = UnmarshalThirdPartyBlockContents(contentsBytes)
			require.NoError(t, err)
			appended, err := token.AppendThirdPartyBlock(nil, thirdPartyPublic, contents)
			require.NoError(t, err)
			require.Equal(t, token.symbols, appended.symbols, "a third-party block must not extend the token's symbol table")
			require.EqualValues(t, 5, appended.blocks[0].version)
			require.NotNil(t, appended.blocks[0].externalKey)

			deser, err := Unmarshal(mustSerialize(t, appended))
			require.NoError(t, err)
			require.Contains(t, deser.Code()[0], `group("admin")`)

			ab, err := deser.AuthorizerFrom(RootKey(publicRoot))
			require.NoError(t, err)
			ab.AddPolicy(DefaultAllowPolicy)
			require.NoError(t, ab.Authorize())
			require.Contains(t, ab.PrintWorld(), "// origin: [1]\ngroup(\"admin\");")

			// A policy trusting the key sees the third-party fact; without it, not.
			query := Rule{Head: Predicate{Name: "query"}, Body: []Predicate{{Name: "group", IDs: []Term{String("admin")}}}}
			ab, err = deser.AuthorizerFrom(RootKey(publicRoot))
			require.NoError(t, err)
			ab.AddPolicy(Policy{Kind: PolicyKindAllow, Queries: []Rule{query}})
			require.ErrorIs(t, ab.Authorize(), ErrNoMatchingPolicy)

			trusted := query
			trusted.Scopes = []Scope{trust}
			ab, err = deser.AuthorizerFrom(RootKey(publicRoot))
			require.NoError(t, err)
			ab.AddPolicy(Policy{Kind: PolicyKindAllow, Queries: []Rule{trusted}})
			require.NoError(t, ab.Authorize())

			// The block is bound to the token it was requested for.
			otherToken, err := NewBuilder(privateRoot).Build()
			require.NoError(t, err)
			_, err = otherToken.AppendThirdPartyBlock(nil, thirdPartyPublic, contents)
			require.ErrorContains(t, err, "invalid external signature")

			// And to the key the holder expects.
			otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
			_, err = token.AppendThirdPartyBlock(nil, otherPub, contents)
			require.ErrorContains(t, err, "third-party block signed by")

			// A builder made from the token would use the token's symbol table.
			_, err = request.CreateBlock(tc.private, token.CreateBlock())
			require.ErrorContains(t, err, "NewThirdPartyBlockBuilder")

			// A tampered payload fails verification.
			tampered := *contents
			tampered.payload = append([]byte{}, contents.payload...)
			tampered.payload[len(tampered.payload)-1] ^= 0xff
			_, err = token.AppendThirdPartyBlock(nil, thirdPartyPublic, &tampered)
			require.Error(t, err)
		})
	}
}

// A third-party block's public keys and symbols are its own: the same key
// in the token table and in the block table resolves independently.
func TestThirdPartyBlockIsolatedTables(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	trust1, _ := TrustingPublicKey(pub1)
	trust2, _ := TrustingPublicKey(pub2)

	builder := NewBuilder(privateRoot)
	require.NoError(t, builder.AddAuthorityFact(Fact{Predicate{Name: "query", IDs: []Term{Integer(0)}}}))
	token, err := builder.Build()
	require.NoError(t, err)

	appendThirdParty := func(token *Biscuit, priv ed25519.PrivateKey, pub ed25519.PublicKey, block func(BlockBuilder)) *Biscuit {
		request, err := token.ThirdPartyRequest()
		require.NoError(t, err)
		bb := NewThirdPartyBlockBuilder()
		block(bb)
		contents, err := request.CreateBlock(priv, bb)
		require.NoError(t, err)
		next, err := token.AppendThirdPartyBlock(nil, pub, contents)
		require.NoError(t, err)
		return next
	}

	// Block 1 (key 1): query(1), and a rule trusting key 2 that joins with block 2.
	token = appendThirdParty(token, priv1, pub1, func(bb BlockBuilder) {
		require.NoError(t, bb.AddFact(Fact{Predicate{Name: "query", IDs: []Term{Integer(1)}}}))
		require.NoError(t, bb.AddRule(Rule{
			Head:   Predicate{Name: "query", IDs: []Term{Integer(1), Integer(2)}},
			Body:   []Predicate{{Name: "query", IDs: []Term{Integer(1)}}, {Name: "query", IDs: []Term{Integer(2)}}},
			Scopes: []Scope{trust2},
		}))
	})
	// Block 2 (key 2): query(2), with a check trusting key 1.
	token = appendThirdParty(token, priv2, pub2, func(bb BlockBuilder) {
		require.NoError(t, bb.AddFact(Fact{Predicate{Name: "query", IDs: []Term{Integer(2)}}}))
		require.NoError(t, bb.AddCheck(Check{Queries: []Rule{{
			Head:   Predicate{Name: "query"},
			Body:   []Predicate{{Name: "query", IDs: []Term{Integer(1)}}},
			Scopes: []Scope{trust1},
		}}}))
	})
	// Block 3 (first party): a check trusting both keys.
	block3 := token.CreateBlock()
	require.NoError(t, block3.AddCheck(Check{Queries: []Rule{{
		Head:   Predicate{Name: "query"},
		Body:   []Predicate{{Name: "query", IDs: []Term{Integer(1), Integer(2)}}},
		Scopes: []Scope{trust1, trust2},
	}}}))
	token, err = token.Append(rand.Reader, block3.Build())
	require.NoError(t, err)
	require.Equal(t, publicKeyTable{trust1.PublicKey, trust2.PublicKey}, token.publicKeys)

	deser, err := Unmarshal(mustSerialize(t, token))
	require.NoError(t, err)
	require.Equal(t, []datalog.PublicKey{trust2.PublicKey}, deser.blocks[0].publicKeys)
	require.Equal(t, []datalog.PublicKey{trust1.PublicKey}, deser.blocks[1].publicKeys)
	require.Equal(t, []datalog.PublicKey{trust1.PublicKey, trust2.PublicKey}, deser.blocks[2].publicKeys)

	ab, err := deser.AuthorizerFrom(RootKey(publicRoot))
	require.NoError(t, err)
	ab.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, ab.Authorize())
	require.Contains(t, ab.PrintWorld(), "// origin: [1, 2]\nquery(1, 2);")
}

// The scopes of the authorizer are the default of its rules as well as of its
// checks and policies, in whatever order they are added: AddAuthorizer adds
// the rules of the block before its scopes.
func TestAuthorizerScopesApplyToItsRules(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	thirdPartyPublic, thirdPartyPrivate, _ := ed25519.GenerateKey(rand.Reader)
	trust, err := TrustingPublicKey(thirdPartyPublic)
	require.NoError(t, err)

	token, err := NewBuilder(privateRoot).Build()
	require.NoError(t, err)
	request, err := token.ThirdPartyRequest()
	require.NoError(t, err)
	block := NewThirdPartyBlockBuilder()
	require.NoError(t, block.AddFact(Fact{Predicate{Name: "group", IDs: []Term{String("admin")}}}))
	contents, err := request.CreateBlock(thirdPartyPrivate, block)
	require.NoError(t, err)
	token, err = token.AppendThirdPartyBlock(nil, thirdPartyPublic, contents)
	require.NoError(t, err)

	// The policy matches a fact that a rule of the authorizer derives from
	// the third-party block.
	authorize := func(scopes ...Scope) error {
		authorizer, err := token.AuthorizerFrom(RootKey(publicRoot))
		require.NoError(t, err)
		authorizer.AddAuthorizer(ParsedAuthorizer{
			Block: ParsedBlock{
				Rules: []Rule{{
					Head: Predicate{Name: "is_admin", IDs: []Term{Bool(true)}},
					Body: []Predicate{{Name: "group", IDs: []Term{String("admin")}}},
				}},
				Scopes: scopes,
			},
			Policies: []Policy{{Kind: PolicyKindAllow, Queries: []Rule{{
				Head: Predicate{Name: "query"},
				Body: []Predicate{{Name: "is_admin", IDs: []Term{Bool(true)}}},
			}}}},
		})
		return authorizer.Authorize()
	}

	require.ErrorIs(t, authorize(), ErrNoMatchingPolicy)
	require.NoError(t, authorize(trust))
}

// A block may refer to the default symbols, to the symbols of the blocks
// before it and to its own. A symbol that only a later block defines is
// refused: that block would decide what the earlier one means.
func TestUnmarshalRejectsUnknownSymbols(t *testing.T) {
	_, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	check := Check{Queries: []Rule{{
		Head: Predicate{Name: "query"},
		Body: []Predicate{{Name: "resource", IDs: []Term{String("file2")}}},
	}}}

	builder := NewBuilder(privateRoot)
	require.NoError(t, builder.AddAuthorityFact(Fact{Predicate{Name: "right", IDs: []Term{String("file1"), String("read")}}}))
	token, err := builder.Build()
	require.NoError(t, err)
	for range 2 {
		block := token.CreateBlock()
		require.NoError(t, block.AddCheck(check))
		token, err = token.Append(rand.Reader, block.Build())
		require.NoError(t, err)
	}
	// Block 1 defines "file2" and block 2 reuses it.
	require.Equal(t, datalog.SymbolTable{"file2"}, *token.blocks[0].symbols)
	require.Empty(t, *token.blocks[1].symbols)

	unmarshal := func(container *pb.Biscuit) error {
		serialized, err := proto.Marshal(container)
		require.NoError(t, err)
		_, err = Unmarshal(serialized)
		return err
	}
	require.NoError(t, unmarshal(token.container))

	// With the definition moved to block 2, the check of block 1 refers to
	// a symbol defined after it, as in the sample test039 of the spec.
	container := proto.Clone(token.container).(*pb.Biscuit)
	editSignedBlock(t, container.Blocks[0], func(b *pb.Block) { b.Symbols = nil })
	editSignedBlock(t, container.Blocks[1], func(b *pb.Block) { b.Symbols = []string{"file2"} })
	err = unmarshal(container)
	require.ErrorIs(t, err, ErrMissingSymbols)
	require.ErrorContains(t, err, "unknown symbol 1025")

	// A third-party block has its own table: it cannot borrow the symbol
	// the token has at the same index.
	thirdPartyPublic, thirdPartyPrivate, _ := ed25519.GenerateKey(rand.Reader)
	request, err := token.ThirdPartyRequest()
	require.NoError(t, err)
	block := NewThirdPartyBlockBuilder()
	require.NoError(t, block.AddFact(Fact{Predicate{Name: "group", IDs: []Term{String("staff")}}}))
	contents, err := request.CreateBlock(thirdPartyPrivate, block)
	require.NoError(t, err)
	token, err = token.AppendThirdPartyBlock(nil, thirdPartyPublic, contents)
	require.NoError(t, err)
	require.NoError(t, unmarshal(token.container))

	container = proto.Clone(token.container).(*pb.Biscuit)
	editSignedBlock(t, container.Blocks[2], func(b *pb.Block) { b.Symbols = nil })
	err = unmarshal(container)
	require.ErrorIs(t, err, ErrMissingSymbols)
	require.ErrorContains(t, err, "unknown symbol 1024")
}

// Unmarshal refuses the signed blocks the spec rules out. It does not verify
// signatures, so the tampered tokens are refused for their shape alone.
func TestUnmarshalRejectsInvalidSignedBlocks(t *testing.T) {
	_, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	thirdPartyPublic, thirdPartyPrivate, _ := ed25519.GenerateKey(rand.Reader)

	token, err := NewBuilder(privateRoot).Build()
	require.NoError(t, err)
	request, err := token.ThirdPartyRequest()
	require.NoError(t, err)
	contents, err := request.CreateBlock(thirdPartyPrivate, NewThirdPartyBlockBuilder())
	require.NoError(t, err)
	token, err = token.AppendThirdPartyBlock(nil, thirdPartyPublic, contents)
	require.NoError(t, err)

	_, err = Unmarshal(mustSerialize(t, token))
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		tamper func(*pb.Biscuit)
		want   string
	}{
		{
			name:   "external signature on the authority block",
			tamper: func(c *pb.Biscuit) { c.Authority.ExternalSignature = c.Blocks[0].ExternalSignature },
			want:   "the authority block cannot carry an external signature",
		},
		{
			name:   "third-party block with a v0 signature",
			tamper: func(c *pb.Biscuit) { c.Blocks[0].Version = nil },
			want:   "third-party blocks require block signature version 1, got 0",
		},
		{
			name:   "unknown signature version",
			tamper: func(c *pb.Biscuit) { c.Authority.Version = proto.Uint32(2) },
			want:   "unsupported block signature version: 2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			container := proto.Clone(token.container).(*pb.Biscuit)
			tc.tamper(container)
			serialized, err := proto.Marshal(container)
			require.NoError(t, err)

			_, err = Unmarshal(serialized)
			require.ErrorContains(t, err, tc.want)
		})
	}
}
