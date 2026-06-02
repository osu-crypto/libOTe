# LogVole

`LogVole` is a semi-honest chosen-input VOLE implementation based on the
Ring-LWE construction from:

Lucien K. L. Ng, Peter Rindal and Akash Shah,
_LogVOLE: Succinct and Efficient Chosen-Input VOLE for ZK and Beyond_, 2026.

The implementation was ported from the `origin/clean-ot` LogVole code path into
libOTe's coproto and build infrastructure.

## Functionality

The public wrapper implements chosen-input VOLE over a batching prime `p`.
For receiver input vector `x` and sender scalar `Delta`, the sender obtains
keys `b`, and the receiver obtains MACs `a` such that

```text
a[i] = b[i] + x[i] * Delta mod p.
```

The receiver chooses `x`; the sender learns only its key vector and `Delta`.
The implementation is semi-honest. It does not add malicious-security checks on
top of the LogVole protocol.

## Dependencies

LogVole is enabled by default and commits to stock Microsoft SEAL 4.1.1 through
the `SEAL::seal` CMake target. With the default libOTe fetch flow,
`FETCH_AUTO=ON` fetches and installs SEAL into the local third-party prefix. Use
`-DENABLE_LOGVOLE=OFF` to omit LogVole, or use `-DFETCH_SEAL=OFF` / `--noauto`
with `SEAL_DIR` to provide an existing stock SEAL install instead.

The coproto socket interface is used for all protocol communication; the
frontend split-role example also needs coproto Boost socket support.

## Public API

The libOTe-facing API is in `LogVole.h`:

```cpp
osuCrypto::LogVoleSender sender;
osuCrypto::LogVoleReceiver receiver;
```

Call `configure(n, plaintextModulusBits, numThreads)` on both parties to select
the request size and plaintext modulus bit count. The actual batching prime is
available through `modulus()` after configuration. The offline phase fixes the
sender's `Delta` and can be reused for sequential online calls of the same size.
Online calls consume an internal SID counter that is reset to zero by `offline()`.

For one-shot local use, the sender can call `send(delta, b, sock)` and the
receiver can call `receive(x, a, sock)`. If the wrapper has not been configured
or run offline yet, the one-shot calls configure and run offline automatically.

Lower-level `osuCrypto::LogVole` functions expose the CI-VOLE state machine,
CRT packing, and recursive ring protocol helpers for tests and internal use.

## Example

The frontend example is enabled with `-logvole`, `-lv`, or `-LogVole`.

Local in-process example:

```text
frontend_libOTe -logvole -n 16
```

Useful options:

```text
-n <count>      number of CI-VOLE outputs
-nn <bits>      use 2^bits outputs
-p <bits>       requested plaintext modulus bit count, default 55
-delta <value>  sender correlation scalar modulo p, default 7
-t <threads>    worker thread count
```

With coproto Boost socket support, the split-role example can be run with the
usual libOTe `-r` sender/receiver option.
