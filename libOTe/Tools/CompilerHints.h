#pragma once

// Keep compiler-specific attributes at one definition site.
#ifndef OC_NOINLINE
#if defined(_MSC_VER)
#define OC_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define OC_NOINLINE __attribute__((noinline))
#else
#define OC_NOINLINE
#endif
#endif
