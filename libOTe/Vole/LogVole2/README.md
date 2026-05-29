# LogVole2 staging area

`LogVole2` is the parallel port of the complete `origin/clean-ot` LogVole implementation.

The final landing step is intended to be a mechanical rename from `LogVole2` to `LogVole` after the recursive protocol and CI-VOLE tests pass in libOTe.

Initial order:

1. Clean-ot-compatible types.
2. Ring and NTT operations, preserving clean-ot structure. Use `__int128` and the clean-ot `cpp_int` centered-decomposition fallback for now; portability/dependency cleanup comes after correctness.
3. LENC/LHE and shrink-expand.
4. Seed-label/root helpers.
5. Recursive sender/receiver over coproto.
6. CI-VOLE wrapper and tests.
