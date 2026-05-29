#pragma once

// Lightweight compiler-specific loop optimization hints used in CPU hot paths.
#if defined(__clang__)
#define LOGVOLE_PRAGMA_UNROLL _Pragma("clang loop unroll(enable)")
#define LOGVOLE_PRAGMA_IVDEP _Pragma("clang loop vectorize(enable)")
#elif defined(__GNUC__)
#define LOGVOLE_PRAGMA_UNROLL _Pragma("GCC unroll 8")
#define LOGVOLE_PRAGMA_IVDEP _Pragma("GCC ivdep")
#else
#define LOGVOLE_PRAGMA_UNROLL
#define LOGVOLE_PRAGMA_IVDEP
#endif
