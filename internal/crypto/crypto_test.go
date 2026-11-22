// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	"slices"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	for _, alg := range []pb.PublicKey_Algorithm{pb.PublicKey_Ed25519, pb.PublicKey_SECP256R1} {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := GenerateSigner(alg, rand.Reader)
			require.NoError(t, err)
			require.Equal(t, alg, signer.Algorithm())

			payload := []byte("payload")
			sig, err := signer.Sign(payload)
			require.NoError(t, err)

			// The public key travels in pb.PublicKey, the secret in pb.Proof.
			verifier, err := ParseVerifier(alg, signer.PublicKey())
			require.NoError(t, err)
			require.NoError(t, verifier.Verify(payload, sig))
			require.ErrorIs(t, verifier.Verify([]byte("other"), sig), ErrInvalidSignature)

			parsed, err := ParseSigner(alg, signer.Secret())
			require.NoError(t, err)
			require.Equal(t, signer.PublicKey(), parsed.PublicKey())
			require.Len(t, signer.Secret(), 32)
		})
	}
}

func TestNewSignerVerifier(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		priv crypto.Signer
		pub  crypto.PublicKey
		alg  pb.PublicKey_Algorithm
	}{
		{"ed25519", edPriv, edPub, pb.PublicKey_Ed25519},
		{"secp256r1", ecPriv, &ecPriv.PublicKey, pb.PublicKey_SECP256R1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := NewSigner(tc.priv)
			require.NoError(t, err)
			verifier, err := NewVerifier(tc.pub)
			require.NoError(t, err)
			require.Equal(t, tc.alg, signer.Algorithm())
			require.Equal(t, tc.alg, verifier.Algorithm())
			require.Equal(t, signer.PublicKey(), verifier.PublicKey())

			sig, err := signer.Sign([]byte("payload"))
			require.NoError(t, err)
			require.NoError(t, verifier.Verify([]byte("payload"), sig))
		})
	}

	_, err = NewSigner(nil)
	require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	_, err = NewVerifier([]byte("not a key"))
	require.ErrorIs(t, err, ErrInvalidKeySize)
	fromBytes, err := NewVerifier([]byte(edPub))
	require.NoError(t, err)
	require.Equal(t, pb.PublicKey_Ed25519, fromBytes.Algorithm())
	_, err = ParseVerifier(pb.PublicKey_SECP256R1, edPub)
	require.ErrorIs(t, err, ErrInvalidKeySize)
}

// littleEndian reads the integer that Ed25519 encodes in b.
func littleEndian(b []byte) *big.Int {
	reversed := slices.Clone(b)
	slices.Reverse(reversed)
	return new(big.Int).SetBytes(reversed)
}

// The table of the points of small order, checked on the curve
// -x² + y² = 1 + d x² y²: eight times each point is the neutral element, and
// the table has the eight points for which that holds.
func TestEd25519SmallOrderTable(t *testing.T) {
	one := big.NewInt(1)
	p := new(big.Int).Sub(new(big.Int).Lsh(one, 255), big.NewInt(19))
	mul := func(a, b *big.Int) *big.Int { m := new(big.Int).Mul(a, b); return m.Mod(m, p) }
	div := func(a, b *big.Int) *big.Int { return mul(a, new(big.Int).ModInverse(new(big.Int).Mod(b, p), p)) }
	d := div(big.NewInt(-121665), big.NewInt(121666))

	type point struct{ x, y *big.Int }
	double := func(a point) point {
		k := mul(d, mul(mul(a.x, a.x), mul(a.y, a.y)))
		return point{
			x: div(new(big.Int).Add(mul(a.x, a.y), mul(a.x, a.y)), new(big.Int).Add(one, k)),
			y: div(new(big.Int).Add(mul(a.y, a.y), mul(a.x, a.x)), new(big.Int).Sub(one, k)),
		}
	}

	points := map[string]bool{}
	for _, encoded := range ed25519SmallOrderY {
		y := littleEndian(encoded[:])
		y.Mod(y, p)
		yy := mul(y, y)
		x := new(big.Int).ModSqrt(div(new(big.Int).Sub(yy, one), new(big.Int).Add(mul(d, yy), one)), p)
		require.NotNil(t, x, "%x is not on the curve", encoded)

		eight := double(double(double(point{x, y})))
		require.Zero(t, eight.x.Sign(), "%x", encoded)
		require.Zero(t, eight.y.Cmp(one), "%x", encoded)

		points[x.String()+","+y.String()] = true
		points[new(big.Int).Mod(new(big.Int).Neg(x), p).String()+","+y.String()] = true
	}
	// The curve has eight points of small order.
	require.Len(t, points, 8)
}

// crypto/ed25519 accepts a public key of small order and a signature whose
// point R has small order. biscuit-rust refuses the two, and so must this
// package, or it accepts tokens that biscuit-rust refuses.
func TestEd25519StrictVerification(t *testing.T) {
	// Under a public key of small order, R || 0 is a signature of a message
	// for one R of small order: nobody needs a secret to make it.
	for _, y := range ed25519SmallOrderY {
		for _, sign := range []byte{0, 0x80} {
			key := slices.Clone(y[:])
			key[31] |= sign
			verifier, err := ParseVerifier(pb.PublicKey_Ed25519, key)
			require.NoError(t, err)
			for i := range 32 {
				for _, r := range ed25519SmallOrderY {
					signature := append(slices.Clone(r[:]), make([]byte, 32)...)
					require.ErrorIs(t, verifier.Verify([]byte{byte(i)}, signature), ErrInvalidSignature, "key %x R %x", key, r)
				}
			}
		}
	}
	neutral := ed25519SmallOrderY[1]
	require.True(t, ed25519.Verify(neutral[:], []byte("payload"), append(slices.Clone(neutral[:]), make([]byte, 32)...)))

	// The holder of a key can make a signature with the neutral element as
	// R: S is then k times the secret scalar, with k = SHA-512(R || A || M).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	h := sha512.Sum512(priv.Seed())
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	scalar := littleEndian(h[:32])
	payload := []byte("payload")
	digest := sha512.Sum512(append(append(slices.Clone(neutral[:]), pub...), payload...))
	k := littleEndian(digest[:])
	order, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	s := new(big.Int).Mul(k, scalar)
	s.Mod(s, order)
	sBytes := s.FillBytes(make([]byte, 32))
	slices.Reverse(sBytes)
	signature := append(slices.Clone(neutral[:]), sBytes...)

	require.True(t, ed25519.Verify(pub, payload, signature))
	verifier, err := NewVerifier(pub)
	require.NoError(t, err)
	require.ErrorIs(t, verifier.Verify(payload, signature), ErrInvalidSignature)

	// A signature that the key made the usual way is accepted.
	require.NoError(t, verifier.Verify(payload, ed25519.Sign(priv, payload)))

	// Under the neutral element as public key, a public key A with its
	// secret scalar a is a signature (A, a) of every message. R is then not
	// of small order: only the check of the public key refuses it.
	aBytes := new(big.Int).Mod(scalar, order).FillBytes(make([]byte, 32))
	slices.Reverse(aBytes)
	forged := append(slices.Clone(pub), aBytes...)
	require.True(t, ed25519.Verify(neutral[:], payload, forged))
	weak, err := ParseVerifier(pb.PublicKey_Ed25519, neutral[:])
	require.NoError(t, err)
	require.ErrorIs(t, weak.Verify(payload, forged), ErrInvalidSignature)

	// A signature that does not have the size of the algorithm is refused
	// before its first half is read: the final signature of a sealed token
	// comes here with the size that the token gives it.
	for _, size := range []int{0, 3, 31, 32, 63, 65} {
		require.NotPanics(t, func() {
			require.ErrorIs(t, verifier.Verify(payload, make([]byte, size)), ErrInvalidSignature, "size %d", size)
		})
	}
}
