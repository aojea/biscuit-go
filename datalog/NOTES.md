# Datalog interpreter: timeout granularity and join rewrite

Working notes for the follow-up to eclipse-biscuit/biscuit-go#195. Branch:
`datalog-budgeted-combine` on `aojea/biscuit-go`, based on the PR #195 head
(`624e0cf`). Measurements below were taken on a noisy VM; re-run with
`-count=6` and `benchstat` before quoting numbers.

## Problem

Since #181 the time limit is checked synchronously, only between rules.
PR #195 adds a check inside `combine` every 16 descents. Measured against a
2 ms budget, that leaves three unbounded loops on the `World.Run` path:

| loop | where | PR #195 lateness |
|---|---|---|
| candidate scan (`Match` + `advanceIndexes`) | `combine` inner loop | 8 µs (only because the PR's test misses on the *last* predicate) |
| full-tuple evaluation (map clone + expressions) | `combine` `match:` block | **5.3 ms** (1000 facts, 2-predicate rule, expression false) |
| fact materialisation (`FactSet.Insert` is O(n), so O(n²)) | `apply` + `Run`'s `InsertAll` | **7 ms** (40 facts, 2-predicate rule) |

Unit costs here: `time.Now()` ≈ 52 ns, one `Match` ≈ 4 ns, `time.AfterFunc`
wake-up latency 170–700 µs. Conclusions that drove the design:

- A timer flipping an atomic flag is free on the hot path but its precision
  is the scheduler's (170 µs+). A synchronous counter polled every ~1k units
  is two orders of magnitude tighter. Don't go back to timers/goroutines.
- Checking the clock per step costs +74 % on scan-heavy joins. Count work,
  poll rarely.

## What biscuit-rust does (reference, `biscuit-auth/src/datalog/mod.rs`)

- `CombineIt` binds variables per level and never descends on a conflict.
  Go's old `combine` enumerated the full cross product (`Match` ignores
  variables) and checked bindings only on complete tuples.
- `FactSet` is `HashMap<Origin, HashSet<Fact>>` → O(1) dedup.
- `max_time` is checked **only between iterations**, after a merge that
  produced new facts. Rust has the same granularity gap; worth raising
  upstream as a spec-level concern.

## What this branch does (two commits on top of #195)

1. `datalog: budgeted backtracking join`
   - `runBudget`: single cooperative cancellation point. Every unbounded
     loop calls `tick(n)`; the clock is polled once per 1024 units. Public
     `Rule.Apply` passes a nil budget (no-op), so `QueryRule` is unchanged.
   - `combine` rewritten as a recursive backtracking search with a binding
     trail (one preallocated cell per variable, deep copy only on emit).
     Same accepted tuples, same enumeration order as before.
   - ticks: one per scan (|facts| units), one per emitted tuple (32), one per
     insert.
2. `datalog: index FactSet duplicates above a size threshold`
   - `factKey`: canonical byte encoding with `key(a)==key(b) ⇔ a.Equal(b)`,
     including `Set.Equal`'s quirk (length-sensitive, order/repetition
     insensitive) → key = len + sorted distinct elements.
     `TestFactKeyMatchesEqual` pins this in both directions.
   - `indexedFacts`: linear `Insert` below `indexThreshold = 32` facts,
     `map[string]struct{}` above. Hashing into a reusable scratch buffer; only
     the inserted key allocates.
   - `World.idx` is lazy: nil after `Clone()`, rebuilt by `indexed()` when
     `len(index) != len(facts)` (covers writes through `Facts()`).

## Results vs PR #195 head (this VM)

| | PR | branch |
|---|---|---|
| lateness, last-pred-miss | 8 µs | 2–10 µs |
| lateness, last-pred-match-all | 5.3 ms | ~6 µs (p90 17 µs) |
| lateness, n² materialisation | 7 ms | ~20 µs (p90 130 µs) |
| `WorldRunJoin/n=200` (pure cross product, PR's worst case) | 120 ms | 83 ms |
| `WorldQueryRule/rights=100` | 35 µs | 7 µs |
| `TransitiveClosure/nodes=24` | 58 ms | 16–20 ms, −95 % allocs |
| `WorldAddFact/facts=1000` | — | −88 % vs commit 1 |

## Semantic changes to be aware of

- **`w.facts` after a timeout.** `Run` can now return
  `ErrWorldRunLimitTimeout` while merging `newFacts` into `w.facts`, leaving
  the world with *some* of that iteration's derived facts. Before (#181/#195)
  a timeout always left `w.facts` exactly as it was at the end of the last
  completed iteration. Harmless for the authorizer (any error aborts
  authorization and the world is discarded), but it is observable through
  `Facts()`. Alternatives if that matters: (a) merge unconditionally and tick
  only before the merge — merge is O(n) now, bounded by `maxFacts` in
  practice; (b) enforce `maxFacts` *during* `apply` so the output set is
  bounded deterministically before the merge starts.
- Fact order and dedup are unchanged: `indexedFacts.insert` appends in the
  same order `FactSet.Insert` did, and the key is exactly equivalent to
  `Equal`.
- `Run` without rules / `WithMaxDuration(0)` still returns timeout via the
  explicit `time.Now()` checks at the top of each iteration.

## Harness

`datalog/lateness_review_test.go` (build tag `review`):
`go test ./datalog -tags review -run TestReviewOvershoot -v`

## Open items

- Decide on the partial-merge semantics above.
- `indexThreshold = 32` was chosen from `WorldAddFact/facts=100` being
  neutral-to-better and `TransitiveClosure/nodes=8` unchanged; re-tune on
  real hardware.
- `tupleCost = 32` / `budgetCheckEvery = 1024` likewise.
- Consider a deterministic work cap (`maxWork`) next to `maxFacts`; the
  wall clock stays for compatibility but a work budget is machine-independent.
- Upstream: biscuit-rust checks `max_time` only between iterations.
