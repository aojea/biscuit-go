// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

// Package crypto wraps the signature algorithms a token can use (Ed25519 and
// ECDSA over secp256r1) behind one Signer / Verifier pair, with the key and
// signature encodings defined by the Biscuit specification.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

var (
	ErrInvalidSignature     = errors.New("biscuit: invalid signature")
	ErrInvalidKeySize       = errors.New("biscuit: invalid key size")
	ErrUnsupportedAlgorithm = errors.New("biscuit: unsupported signature algorithm")
)

// Signer signs block payloads with a private key of one algorithm.
type Signer interface {
	Sign(payload []byte) ([]byte, error)
	Algorithm() pb.PublicKey_Algorithm
	// PublicKey is the public key encoded as the spec requires in pb.PublicKey.Key.
	PublicKey() []byte
	// Secret is the private key encoded as the spec requires in pb.Proof.NextSecret.
	Secret() []byte
}

// Verifier checks block signatures with a public key of one algorithm.
type Verifier interface {
	Verify(payload, signature []byte) error
	Algorithm() pb.PublicKey_Algorithm
	PublicKey() []byte
}

// NewSigner accepts an ed25519.PrivateKey or an *ecdsa.PrivateKey on the P-256 curve.
func NewSigner(key crypto.Signer) (Signer, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, ErrInvalidKeySize
		}
		return ed25519Signer{k}, nil
	case *ecdsa.PrivateKey:
		if k == nil || k.Curve != elliptic.P256() {
			return nil, ErrUnsupportedAlgorithm
		}
		return secp256r1Signer{k}, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedAlgorithm, key)
	}
}

// NewVerifier accepts an ed25519.PublicKey or an *ecdsa.PublicKey on the P-256
// curve. A plain []byte is taken as an Ed25519 key, which is what callers
// passed before other algorithms were supported.
func NewVerifier(key crypto.PublicKey) (Verifier, error) {
	switch k := key.(type) {
	case []byte:
		return NewVerifier(ed25519.PublicKey(k))
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, ErrInvalidKeySize
		}
		return ed25519Verifier{k}, nil
	case *ecdsa.PublicKey:
		if k == nil || k.Curve != elliptic.P256() {
			return nil, ErrUnsupportedAlgorithm
		}
		return secp256r1Verifier{k}, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedAlgorithm, key)
	}
}

// ParseVerifier decodes a public key as stored in pb.PublicKey.
func ParseVerifier(alg pb.PublicKey_Algorithm, raw []byte) (Verifier, error) {
	switch alg {
	case pb.PublicKey_Ed25519:
		if len(raw) != ed25519.PublicKeySize {
			return nil, ErrInvalidKeySize
		}
		return ed25519Verifier{ed25519.PublicKey(raw)}, nil
	case pb.PublicKey_SECP256R1:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw)
		if x == nil {
			return nil, ErrInvalidKeySize
		}
		return secp256r1Verifier{&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}
}

// ParseSigner decodes a private key as stored in pb.Proof.NextSecret.
func ParseSigner(alg pb.PublicKey_Algorithm, raw []byte) (Signer, error) {
	switch alg {
	case pb.PublicKey_Ed25519:
		if len(raw) != ed25519.SeedSize {
			return nil, ErrInvalidKeySize
		}
		return ed25519Signer{ed25519.NewKeyFromSeed(raw)}, nil
	case pb.PublicKey_SECP256R1:
		key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
		if err != nil {
			return nil, ErrInvalidKeySize
		}
		return secp256r1Signer{key}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}
}

// GenerateSigner creates a fresh key of the given algorithm.
func GenerateSigner(alg pb.PublicKey_Algorithm, rng io.Reader) (Signer, error) {
	switch alg {
	case pb.PublicKey_Ed25519:
		_, key, err := ed25519.GenerateKey(rng)
		if err != nil {
			return nil, err
		}
		return ed25519Signer{key}, nil
	case pb.PublicKey_SECP256R1:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rng)
		if err != nil {
			return nil, err
		}
		return secp256r1Signer{key}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}
}

type ed25519Signer struct{ key ed25519.PrivateKey }

func (s ed25519Signer) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(s.key, payload), nil
}
func (s ed25519Signer) Algorithm() pb.PublicKey_Algorithm { return pb.PublicKey_Ed25519 }
func (s ed25519Signer) PublicKey() []byte                 { return s.key.Public().(ed25519.PublicKey) }
func (s ed25519Signer) Secret() []byte                    { return s.key.Seed() }

type ed25519Verifier struct{ key ed25519.PublicKey }

// Verify refuses what crypto/ed25519 does and also a public key or a
// signature point R of small order, as biscuit-rust does (verify_strict of
// ed25519-dalek). A point of small order needs no secret: every message has
// a signature that verifies under a public key of small order.
func (v ed25519Verifier) Verify(payload, signature []byte) error {
	if len(signature) != ed25519.SignatureSize ||
		ed25519SmallOrder(v.key) || ed25519SmallOrder(signature[:32]) ||
		!ed25519.Verify(v.key, payload, signature) {
		return ErrInvalidSignature
	}
	return nil
}
func (v ed25519Verifier) Algorithm() pb.PublicKey_Algorithm { return pb.PublicKey_Ed25519 }
func (v ed25519Verifier) PublicKey() []byte                 { return v.key }

// ed25519SmallOrderY are the encodings of the y coordinate of the eight
// points of the curve whose order is 1, 2, 4 or 8, the last two being the
// encodings of 0 and 1 that are not reduced: crypto/ed25519 and
// ed25519-dalek both accept them.
var ed25519SmallOrderY = [...][32]byte{
	{},     // 0, order 4
	{0x01}, // 1, order 1
	{ // order 8
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	},
	{ // order 8
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	},
	{ // p-1, order 2
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	},
	{ // p, which is 0
		0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	},
	{ // p+1, which is 1
		0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	},
}

// ed25519SmallOrder reports whether the 32 bytes encode a point of small
// order. The top bit is the sign of x and does not change the order.
func ed25519SmallOrder(point []byte) bool {
	if len(point) != 32 {
		return false
	}
	var y [32]byte
	copy(y[:], point)
	y[31] &= 0x7f
	for i := range ed25519SmallOrderY {
		if y == ed25519SmallOrderY[i] {
			return true
		}
	}
	return false
}

// secp256r1 keys use the SEC1 compressed point for the public key, the big
// endian scalar for the secret, and ASN.1 DER (r, s) for signatures over SHA-256.
type secp256r1Signer struct{ key *ecdsa.PrivateKey }

func (s secp256r1Signer) Sign(payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}
func (s secp256r1Signer) Algorithm() pb.PublicKey_Algorithm { return pb.PublicKey_SECP256R1 }
func (s secp256r1Signer) PublicKey() []byte {
	return elliptic.MarshalCompressed(elliptic.P256(), s.key.X, s.key.Y)
}
func (s secp256r1Signer) Secret() []byte {
	secret := make([]byte, 32)
	s.key.D.FillBytes(secret)
	return secret
}

type secp256r1Verifier struct{ key *ecdsa.PublicKey }

func (v secp256r1Verifier) Verify(payload, signature []byte) error {
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(v.key, digest[:], signature) {
		return ErrInvalidSignature
	}
	return nil
}
func (v secp256r1Verifier) Algorithm() pb.PublicKey_Algorithm { return pb.PublicKey_SECP256R1 }
func (v secp256r1Verifier) PublicKey() []byte {
	return elliptic.MarshalCompressed(elliptic.P256(), v.key.X, v.key.Y)
}
