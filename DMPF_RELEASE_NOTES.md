# DMPF package compatibility and release scope

This research package includes reusable Waterfall and Reverse-Cuckoo DMPFs.
It is not a claim of production security for every caller or parameter set.

## Upgrade both parties together

The sparse-DPF setup protocol now masks inactive levels and omits the
selected correction's low bit. The masking step changes the OT reservation
and consumption schedule. Recompute reservations through `baseOtCount()`;
do not reuse hard-coded counts or old preprocessing.

The correction encoding and AES schedules also change. Both peers must use
the same revision. Discard old cached DPF state and rerun setup; mixing peers
or cached state from different revisions is unsupported.

`RegularDpfKey` serialization now stores an additional 16-byte public tree
seed. Old serialized keys are incompatible. There is no format negotiation
or migration reader; regenerate keys using the new implementation. Applications
that persist keys should version their own containing format.

Standalone tree generation without a supplied public seed exchanges one
16-byte contribution in each direction. The DMPF wrappers derive their tree
seeds from existing setup coins, so this adds no DMPF messages or OTs.
Leaf expansion advances a public root deterministically and rekeys every
1,024 leaf positions. Internal-node schedules also limit a key to 1,024
distinct parent positions. These schedules are hardening, not a proof of
the inherited AES evaluator.

## Security and parameter boundaries

- Waterfall's generic simulation argument uses ideal subprotocols; the
  concrete AES realization has separate, explicitly conjectured requirements.
- `compact4N()` and `compact3N()` are profiles for 16 input rows, not generic
  parameter generators. Other sizes require their own routing-error analysis.
- Reverse Cuckoo leaks support information and requires the stated
  application-specific assumption. Do not use it as a generic private DMPF.
- Ring-LPN setup filters the analyzed Goldilocks profile: ring degree 2^20,
  four polynomials, and weight 16. Each party resamples its complete support
  tuple until at least 61 residues modulo 128 are occupied, counting each
  polynomial separately. The filter applies to both DMPF backends and both
  OLE/triple output modes, based on the rounded ring degree. Other fields,
  degrees, and noise dimensions retain unfiltered sampling; they have no
  security claim from this profile. Accepted supports persist across reuse.
- A complete application-level OLE simulation/composition argument remains
  separate from the DMPF proof. Historical timing tables predate the full
  set of mask, filtering, and AES changes; they are not current-release
  benchmarks.

## Validation

The registered unit tests include the correction-encoding and inactive-level
regressions, both rekeying schedules, and Waterfall/Reverse-Cuckoo integration.
Enable `ENABLE_SPARSE_DPF`, or use the existing `ENABLE_ALL_OT` CI configuration.
The focused WSL runner is `bash analysis/run_sparse_dpf_mask_tests.sh` after
configuring a compatible Ninja build; `SPARSE_DPF_BUILD` selects its directory.

The exact hash-conditioning checks use only the Python standard library:

```sh
python -m unittest analysis.test_rev_cuckoo_hash_conditioning
```

Do not run two benchmarks concurrently. Record the tested commit, build
configuration, hardware, and raw output when refreshing performance results.
