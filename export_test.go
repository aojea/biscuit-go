// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import "github.com/eclipse-biscuit/biscuit-go/v2/datalog"

// Test-only access to internals for the external test package.

// NewUnsignedBiscuitForTest assembles a token from already built blocks. The
// first block is the authority. Blocks must have been built from the same
// symbol table, in order, so that symbols holds the union of their symbols.
func NewUnsignedBiscuitForTest(symbols *datalog.SymbolTable, blocks ...*Block) *Biscuit {
	return &Biscuit{authority: blocks[0], blocks: blocks[1:], symbols: symbols}
}

// BlockSymbolsForTest returns the symbols a built block introduced.
func BlockSymbolsForTest(b *Block) *datalog.SymbolTable {
	return b.symbols
}

// DefaultSymbolTableForTest returns a copy of the default symbol table.
func DefaultSymbolTableForTest() *datalog.SymbolTable {
	return defaultSymbolTable.Clone()
}

// AuthorizerWorldsForTest returns the authority world and the per-block
// worlds built by the last Authorize call, with the symbols to print them.
func AuthorizerWorldsForTest(a Authorizer) (world *datalog.World, blockWorlds []*datalog.World, symbols *datalog.SymbolTable) {
	v := a.(*authorizer)
	return v.world, v.block_worlds, v.symbols
}
