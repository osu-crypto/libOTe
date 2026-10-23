# Internal-node rekeying

2026-09-07. This pass extends the approved counter-based rekeying to tree
setup. Reusable cached-leaf conversion is unchanged from the preceding pass.
One parent expansion produces two children and consumes one counter position.

## Public seed and lifetime

`setTreeHashSeed(seed)` supplies already-agreed public coins for the next
RegularDPF key generation or SparseDPF expansion. Both parties must supply the
same seed, or both must leave it unset. The supplied seed is consumed once;
initialization, clearing, and moving an object clear the source's pending seed.
Without a supplied seed, the parties exchange one fresh 128-bit block each
and XOR the blocks. This fallback is for standalone calls.

Rev-Cuckoo and Waterfall supply purpose-separated seeds derived from their
existing public setup coins. Waterfall also separates its scatter DPF.
SparseDPF derives separate streams for the dense prefix and sparse suffix.
Consequently, DMPF setup adds no messages or OTs. Standalone calls without a
supplied seed add a 16-byte message in each direction before tree generation.

`RegularDpfKey` stores the public tree seed beside its private root seed.
Serialization grows by 16 bytes per key object, not per tree. Old serialized
keys are incompatible with the new format. Both communicating parties must
update together. The direct cleartext key generator samples one common public
tree seed for its two output keys.

## Counter rules

For stream seed R and counter j, the AES key is
`AES_R(block(j / 1024, 0x445046545245454b))`, with integer division.
The stream caches the expanded AES key until the chunk changes.

Sparse expansion starts its counter at zero. It first counts the
dense-to-sparse boundary roots that actually expand into two children.
It then continues through the existing descending-level, ascending-tree,
ascending-node traversal. Empty nodes and direct leaf assignments do not
consume counter positions. Both parties follow this same public traversal.
Chunk boundaries can split an eight-node packet; the kernel uses a scalar
tail at that boundary and then resumes eight-node batches.

Dense generation and evaluation cannot use an unrecoverable call counter:
compact generation replays levels, and evaluation walks physical buffers
backwards. Each tree therefore reserves a counter range of its padded domain
size. If D is the full tree depth, tree t's level d begins at
`t * 2^D + 2^d`. Here tree indices are zero-based and internal levels satisfy
1 <= d < D. Positions 0 and 1 within each tree's range are unused.
These two unused positions keep all eight-node packets within a single chunk.
Each chunk contains at most 1,024 distinct parent expansions.

At each replayed level, restore that counter base and add the physical buffer
offset. Reversing traversal changes the order of counter visits, not their
keys. The cleartext key generator converts its active logical prefix into
the same eight-subtree physical order. It already knows the cleartext target;
the interactive protocol instead evaluates every public node.

## Execution and security scope

Sparse key setup occurs outside the existing eight-node AES loops. Dense
packets use a cached chunk lookup; this can revisit earlier keys during
recomputation. There are no per-node identifiers or allocated node-key tables.
The sparse stream has one aligned, owned allocation per call. Dense AES
schedules live in non-inlined, non-coroutine kernels. This prevents SIMD
scratch from entering coroutine frames.

The child formulas, correction messages, and leaf conversion formulas are
unchanged. Only the internal AES keys change. This limits the number of
distinct parents evaluated with one chunk key; repeated computation of a
parent deliberately uses the same key. It does not prove the concrete AES
generator secure or eliminate collisions within a chunk.

## Validation

The focused runner now includes dense interactive key generation, regular
evaluation, serialization, and the general DPF audit. The new counter test
covers reverse/replayed chunk visits and cleartext-key evaluation over domains
2, 7, 8, 9, 1023, 1024, 1025, and 4097. Sparse kernel tests begin at counter
1019 and cover 1, 8, 13, 1023, 1024, and 1025 parents, checking against scalar
AES evaluation. Existing tests cover empty sets, singleton sets, skipped
levels, dense-prefix boundaries, and both DMPF constructions.

All 23 focused WSL/GCC tests passed with default parameters and with
`-domain 4097`. The audit fixture formerly expected empty sparse sets to be
rejected, despite their use by Waterfall. It now checks that an empty set
emits no leaves, while retaining the unsorted, duplicate, and out-of-domain
rejection checks. Empty/singleton local-only fixtures supply the public seed
explicitly instead of attempting seed agreement on an unconnected socket.

## End-to-end measurements

`run_internal_node_e2e_benchmark.sh` compares the frozen post-leaf-rekey,
pre-internal-rekey executable against this change. The frozen baseline SHA256
is `26fd9267e5ec491bf4a03b37cd932ffe1d1cf9835c2c93b112664e6cd931f112`.
The final no-inline annotation on cleartext key generation is not exercised
by this interactive benchmark. Both binaries already contain leaf rekeying
and eight-block leaf batching; this is not a comparison to the original
fixed-key leaf kernel.

The fixture uses WSL Ubuntu 24.04, GCC 13.3.0, configured `-O2` with AES-NI
and AVX2, t=16, N=2^20, one set, and additive u64 values. Correlated OTs are
preloaded outside the timers. Both parties run on one thread with
LocalAsyncSocket. Setup is measured once per process; each process performs
three warmup expansions and fifteen timed expansions, checking every full
output outside the timer. Thus the measurements exclude OT preprocessing
and real network latency. Two independent sequential ABBA passes produce
24 runs and 432 checked expansions. No benchmarks ran concurrently.

The table reports each pass separately: setup uses the mean of two timings
per binary; expansion uses the mean of the two per-run medians. Positive
percentages mean slower after internal rekeying.

| Profile | Pass | Setup before / after (ms) | Setup change | Expand before / after (ms) | Expand change |
| --- | --- | --- | --- | --- | --- |
| Waterfall 4N | 1 | 824.96 / 853.96 | +3.52% | 49.795 / 49.877 | +0.17% |
| Waterfall 4N | 2 | 845.34 / 703.61 | -16.77% | 47.441 / 46.650 | -1.67% |
| Waterfall 3N | 1 | 547.53 / 606.83 | +10.83% | 40.137 / 42.752 | +6.52% |
| Waterfall 3N | 2 | 514.47 / 507.59 | -1.34% | 36.892 / 38.006 | +3.02% |
| Rev-Cuckoo 3N | 1 | 2218.03 / 2257.46 | +1.78% | 30.004 / 31.586 | +5.27% |
| Rev-Cuckoo 3N | 2 | 2068.86 / 2031.70 | -1.80% | 27.112 / 28.367 | +4.63% |

Setup variation is too large to isolate a small rekeying overhead. The
reusable leaf source kernel is unchanged, but the 3N and Rev-Cuckoo timing
increases recur in both passes and should not be dismissed as established
noise. Their cause has not been isolated. Follow up with same-cache inputs
and stage-level timings before claiming unchanged expansion performance.
No zero-overhead or statistically significant speedup claim follows here.
Expansion communication remains 4,800 bytes (4N), 12,992 bytes (3N), and
4,656 bytes (Rev-Cuckoo 3N). The Rev-Cuckoo comparison is computational only;
it does not assert equivalent leakage/security. Raw runs are in
`internal_node_e2e_results.csv`.

Follow-up: `internal_node_timing_investigation.md` records a one-executable
generator comparison, identical-cache replay, and affinity-controlled runs
of the frozen binaries. The earlier 5--7% slowdown does not reproduce under
those controls. The frozen-binary difference reverses sign; the one-executable
comparison leaves 1--2% differences. Keep the original observations above as
history, not as an established intrinsic overhead. No production change was
needed for this timing investigation.
