// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

// Package datalog implements the Datalog engine that evaluates Biscuit
// tokens: facts, rules with expressions, and a World that derives facts to a
// fixpoint under run limits.
//
// # Evaluation
//
// World.Run is a naive fixpoint: every iteration applies every rule to the
// current facts, merges what was derived, and stops when nothing new
// appeared. A rule is applied by a backtracking join over its body
// predicates. Variables are bound level by level, so a tuple is pruned at the
// first predicate that contradicts an earlier binding, as biscuit-rust's
// CombineIt does. Each level only visits the facts the index returns for the
// predicate's constant and already bound terms, and the index keeps facts in
// insertion order, so facts are derived in the order a linear scan would
// produce them. A fact that contains a variable matches nothing.
//
// Facts are deduplicated by Predicate.Equal. Above a small size the FactSet
// is backed by a key index: the key of a fact is a canonical encoding such
// that two facts have the same key if and only if they are Equal, including
// Set.Equal, which is sensitive to length but not to order or repetition.
//
// # Run limits
//
// A World stops with ErrWorldRunLimitMaxFacts, ErrWorldRunLimitMaxIterations
// or ErrWorldRunLimitTimeout. The reference implementation checks its time
// limit only between iterations. Here every unbounded loop on the Run path
// reports its work to a budget that polls the clock once per
// budgetCheckEvery units, so the deadline is observed within microseconds
// without paying for a clock read per step; a timer flipping a flag would be
// cheaper still but its precision is the scheduler's. The facts an iteration
// derives are merged all or nothing, so a timeout leaves the world exactly
// as some completed iteration left it. Rule.Apply and World.QueryRule run
// without a budget.
//
// # Testing against the reference
//
// The unit tests in this package port biscuit-rust's datalog tests, and
// TestWorldRunMatchesNaive checks the join against a naive cross-product
// evaluator on generated programs (FuzzWorldRunMatchesNaive exposes the same
// check to the fuzzer). The conformance samples of the specification are run
// through the parser and this engine by TestConformanceWorlds in the root
// package, which compares the facts of every block scope with the world the
// reference derives.
package datalog
