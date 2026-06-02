# LogVole staging area

`LogVole` is the libOTe port of the complete `origin/clean-ot` LogVole implementation.

Initial order:

1. Clean-ot-compatible types.
2. Ring and NTT operations, preserving clean-ot structure. Use `__int128` and the clean-ot `cpp_int` centered-decomposition fallback for now; portability/dependency cleanup comes after correctness.
3. LENC/LHE and shrink-expand.
4. Seed-label/root helpers.
5. Recursive sender/receiver over coproto.
6. CI-VOLE wrapper and tests.
