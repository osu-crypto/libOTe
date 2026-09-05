# Waterfall DMPF implementation

Waterfall builds a reusable distributed multipoint function from a hidden
cuckoo-style placement. The implementation separates the expensive setup from
the repeated payload expansion path.

## Dimensions and representations

For `s` independent sets, `t` input rows per set, and a configuration with
`w` partitions:

- `points` is an `s x t` matrix of XOR-shared domain indices.
- Each row has one candidate column in every partition.
- `P` is the logical `t x m` position map within a set, where `m` is the sum of
  the partition sizes. Its MPC representation is a flattened bit vector.
- A placement is a subvector of `P`: an active row selects exactly one of its
  candidate columns, while a dummy or unplaced row selects none.
- `mSparseSets` contains `s * m` public sparse sets. Each entry lists all domain
  points hashing to that tree's column.

The public `WaterfallConfig` describes only the partition sizes and bounded
repair limit. `compact3N()` and `compact4N()` are concrete profiles generated
for `t=16`; they are not generic parameter generators.

## Setup: `setPoints`

1. **Deduplicate.** Equal points within each set are merged. The first copy is
   active and later copies use the dummy address.
2. **Generate candidates.** The parties sample shared public-hash descriptors
   and evaluate one candidate in every partition for each active row.
3. **Place and repair.** `WaterfallBasic` greedily fills the partitions in
   order. `WaterfallReachability` applies the configured bounded alternating
   path repair. The remaining overflow is a secret-shared correctness-error
   indicator; it is not opened by the protocol.
4. **Materialize sparse sets.** The public hash descriptors define the domain
   points belonging to every column. Empty public columns are retained as empty
   zero-output DPF trees; they can contain no real address and need no special
   failure event. The implementation uses a packed ANF path when the degree and
   partition widths permit it.
5. **Hide and scatter placement records.** `WaterfallScatter` applies two
   serial Waksman passes. Party `p` privately controls pass `p`, so their
   composition is exactly uniform even conditioned on either party's view.
   Only the uniformly permuted placement rows are opened. The records are then
   inverse-routed to obtain the active column addresses and XOR shares of each
   input row's destination column.
6. **Cache punctured DPF leaves.** One sparse DPF is generated for every output
   column. A second family of point DPFs caches the hidden row-to-column map.
   These leaves, tags, and multiplication correlations are reused by every
   later expansion.

Calling `setPoints` twice without `init` is an error. Calling `init` starts a
fresh lifecycle and discards all cached setup state.

## Online expansion: `expand`

1. Deduplicate the payload values using the equality state from setup.
2. Evaluate the cached row-to-column point DPFs and accumulate each value into
   its hidden destination column.
3. Expand the cached sparse-DPF leaves for every column, apply the per-tree
   correction, and reveal only the correction value.
4. Accumulate the corrected sparse leaves into one dense domain output per set.

The native `u64`/integer-ring path batches all deduplication products and uses
the specialized conditional-negation kernel. Other coefficient types use the
same protocol through `CoeffCtx`. The explicit eight-lane loops in
`CachedDpfExpansion.h` are deliberate hot-path code and should remain unrolled
unless measurements justify changing them.

## Correctness and security invariants

- The domain is a power of two, at most `2^32`, because sparse-set indices are
  stored as `u32`.
- The current placement MPC requires a power-of-two `t`.
- Every configured partition size is a power of two.
- Corresponding sparse sets, cached leaf shares, cached tags, and expanded rows
  always have identical leaf order and size.
- The same sampled serial permutation is used for the forward placement pass
  and its inverse record pass.
- Placement overflow is the configuration's bounded correctness error. The
  implementation does not turn it into an explicit protocol abort. A failed
  opened placement can expose which shuffled rows were not placed, so the
  paper also charges the same bounded event in the statistical simulation
  loss.

## Tests and benchmark

`Waterfall_Tests.cpp` covers configuration validation, cleartext placement,
hashing, candidate generation, basic placement, repair, exact scatter, and
end-to-end DMPF expansion over several coefficient types. The frontend
benchmark accepts `--waterfallDmpf --profile 3|4`; both built-in profiles require
`--numPoints 16`.
