// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"google.golang.org/protobuf/proto"
)

// tokenBlockToProtoBlock serializes a block. keys is the key table of the
// token before this block; the keys the block introduces come after.
func tokenBlockToProtoBlock(input *Block, keys publicKeyTable) (*pb.Block, error) {
	if err := checkUTF8(*input.symbols, input.context); err != nil {
		return nil, fmt.Errorf("biscuit: failed to convert token block to proto block: %w", err)
	}
	keys, err := keys.extend(input.publicKeys...)
	if err != nil {
		return nil, err
	}
	out := &pb.Block{
		Symbols: *input.symbols,
		Context: proto.String(input.context),
		Version: proto.Uint32(input.version),
	}
	for _, k := range input.publicKeys {
		out.PublicKeys = append(out.PublicKeys, tokenPublicKeyToProtoPublicKey(k))
	}
	if out.Scope, err = tokenScopesToProtoScopes(input.scopes, keys); err != nil {
		return nil, err
	}

	facts := input.facts
	if facts != nil {
		out.Facts = make([]*pb.Fact, len(*facts))
		var err error
		for i, fact := range *facts {
			out.Facts[i], err = tokenFactToProtoFactV2(fact)
			if err != nil {
				return nil, err
			}
		}
	}

	rules := input.rules
	if rules != nil {
		out.Rules = make([]*pb.Rule, len(rules))
		for i, rule := range rules {
			r, err := tokenRuleToProtoRuleV2(rule, keys)
			if err != nil {
				return nil, err
			}
			out.Rules[i] = r
		}
	}

	checks := input.checks
	if checks != nil {
		out.Checks = make([]*pb.Check, len(checks))
		for i, check := range checks {
			c, err := tokenCheckToProtoCheckV2(check, keys)
			if err != nil {
				return nil, err
			}
			out.Checks[i] = c
		}
	}

	return out, nil
}

// checkUTF8 refuses the symbols and the context of a block, or the symbols
// of saved policies, that are not valid UTF-8. The schema is a proto2
// schema, and the protobuf library does not check a string of such a
// schema. biscuit-rust refuses a block with a string that is not UTF-8. The
// builders refuse what Unmarshal refuses, so that the tokens that they make
// can be read.
func checkUTF8(symbols []string, context string) error {
	for _, symbol := range symbols {
		if !utf8.ValidString(symbol) {
			return errors.New("a symbol is not valid UTF-8")
		}
	}
	if !utf8.ValidString(context) {
		return errors.New("the context is not valid UTF-8")
	}
	return nil
}

// protoBlockToTokenBlock deserializes a block. keys is the key table of the
// token before this block; the keys the block introduces come after.
func protoBlockToTokenBlock(input *pb.Block, keys publicKeyTable) (*Block, error) {
	if err := checkUTF8(input.Symbols, input.GetContext()); err != nil {
		return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: %w", err)
	}

	symbols := datalog.SymbolTable(input.Symbols)

	var facts datalog.FactSet
	var rules []datalog.Rule
	var checks []datalog.Check

	var publicKeys []datalog.PublicKey
	for _, pbKey := range input.PublicKeys {
		key, err := protoScopeKeyToTokenPublicKey(pbKey)
		if err != nil {
			return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: %w", err)
		}
		publicKeys = append(publicKeys, key)
	}
	keys, err := keys.extend(publicKeys...)
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: %w", err)
	}

	scopes, err := protoScopesToTokenScopes(input.Scope, keys)
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: %w", err)
	}

	if input.GetVersion() < MinSchemaVersion {
		return nil, fmt.Errorf(
			"biscuit: failed to convert proto block to token block: block version: %d < library version %d",
			input.GetVersion(),
			MinSchemaVersion,
		)
	}
	if input.GetVersion() > MaxSchemaVersion {
		return nil, fmt.Errorf(
			"biscuit: failed to convert proto block to token block: block version: %d > library version %d",
			input.GetVersion(),
			MaxSchemaVersion,
		)
	}

	switch input.GetVersion() {
	case blockVersion3_0, blockVersion3_1, blockVersion3_2, blockVersion3_3:
		facts = make(datalog.FactSet, len(input.Facts))
		rules = make([]datalog.Rule, len(input.Rules))
		checks = make([]datalog.Check, len(input.Checks))

		for i, pbFact := range input.Facts {
			f, err := protoFactToTokenFactV2(pbFact)
			if err != nil {
				return nil, err
			}
			facts[i] = *f
		}

		for i, pbRule := range input.Rules {
			r, err := protoRuleToTokenRuleV2(pbRule, keys)
			if err != nil {
				return nil, err
			}
			rules[i] = *r
		}

		for i, pbCheck := range input.Checks {
			// The kind of a check is a field of datalog v3.1. A v3.0 block
			// that has it, also with the default kind, is not valid.
			if pbCheck.Kind != nil && input.GetVersion() < blockVersion3_1 {
				return nil, errBlockVersion(input.GetVersion(), blockVersion3_1)
			}
			c, err := protoCheckToTokenCheckV2(pbCheck, keys)
			if err != nil {
				return nil, err
			}
			checks[i] = *c
		}
	default:
		return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: unsupported version: %d", input.GetVersion())
	}

	if required := readableVersion(facts, scopes, rules, checks); input.GetVersion() < required {
		return nil, errBlockVersion(input.GetVersion(), required)
	}

	return &Block{
		symbols:    &symbols,
		facts:      &facts,
		rules:      rules,
		checks:     checks,
		scopes:     scopes,
		publicKeys: publicKeys,
		context:    input.GetContext(),
		version:    input.GetVersion(),
	}, nil
}

// errBlockVersion reports a block that declares a version lower than the
// version that its content needs.
func errBlockVersion(declared, needed uint32) error {
	return fmt.Errorf(
		"biscuit: failed to convert proto block to token block: block version %d uses features of version %d",
		declared,
		needed,
	)
}

/*func tokenSignatureToProtoSignature(ts *sig.TokenSignature) *pb.Signature {
	params, z := ts.Encode()
	return &pb.Signature{
		Parameters: params,
		Z:          z,
	}
}

func protoSignatureToTokenSignature(ps *pb.Signature) (*sig.TokenSignature, error) {
	return sig.Decode(ps.Parameters, ps.Z)
}*/
