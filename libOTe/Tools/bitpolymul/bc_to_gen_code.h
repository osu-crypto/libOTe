#pragma once

#include "libOTe/config.h"
#ifdef ENABLE_SILENTOT

#include <immintrin.h>
#define x(v1, v2) _mm256_xor_si256(v1,v2)
#define m __m256i

#define BOOST_PP_CAT(a, b) BOOST_PP_CAT_I(a, b)
#define BOOST_PP_CAT_I(a, b) a ## b

#if _MSC_VER
#    define BOOST_PP_VARIADIC_SIZE(...) BOOST_PP_CAT(BOOST_PP_VARIADIC_SIZE_I(__VA_ARGS__, 64, 63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,),)
#else
#    define BOOST_PP_VARIADIC_SIZE(...) BOOST_PP_VARIADIC_SIZE_I(__VA_ARGS__, 64, 63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,)
#endif
#define BOOST_PP_VARIADIC_SIZE_I(e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, e13, e14, e15, e16, e17, e18, e19, e20, e21, e22, e23, e24, e25, e26, e27, e28, e29, e30, e31, e32, e33, e34, e35, e36, e37, e38, e39, e40, e41, e42, e43, e44, e45, e46, e47, e48, e49, e50, e51, e52, e53, e54, e55, e56, e57, e58, e59, e60, e61, e62, e63, size, ...) size


inline void xorEq_1(m* v1, m v2) { *v1 = x(*v1, v2); }
inline void xorEq_2(m* v1, m v2, m v3) { *v1 = x(x(*v1, v2), v3); }
inline void xorEq_3(m* v1, m v2, m v3, m v4) { *v1 = x(x(x(*v1, v2), v3), v4); }
inline void xorEq_4(m* v1, m v2, m v3, m v4, m v5) { *v1 = x(x(x(x(*v1, v2), v3), v4), v5); }
inline void xorEq_5(m* v1, m v2, m v3, m v4, m v5, m v6) { *v1 = x(x(x(x(x(*v1, v2), v3), v4), v5), v6); }
inline void xorEq_6(m* v1, m v2, m v3, m v4, m v5, m v6, m v7) { *v1 = x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7); }
inline void xorEq_7(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8) { *v1 = x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8); }
inline void xorEq_8(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9) { *v1 = x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9); }
inline void xorEq_9(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10) { *v1 = x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10); }
inline void xorEq_10(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11) { *v1 = x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11); }
inline void xorEq_11(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12) { *v1 = x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12); }
inline void xorEq_12(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12, m v13) { *v1 = x(x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12), v13); }
inline void xorEq_13(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12, m v13, m v14) { *v1 = x(x(x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12), v13), v14); }
inline void xorEq_14(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12, m v13, m v14, m v15) { *v1 = x(x(x(x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12), v13), v14), v15); }
inline void xorEq_15(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12, m v13, m v14, m v15, m v16) { *v1 = x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12), v13), v14), v15), v16); }
inline void xorEq_16(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12, m v13, m v14, m v15, m v16, m v17) { *v1 = x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12), v13), v14), v15), v16), v17); }
inline void xorEq_17(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12, m v13, m v14, m v15, m v16, m v17, m v18) { *v1 = x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12), v13), v14), v15), v16), v17), v18); }
inline void xorEq_18(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12, m v13, m v14, m v15, m v16, m v17, m v18, m v19) { *v1 = x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12), v13), v14), v15), v16), v17), v18), v19); }
inline void xorEq_19(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12, m v13, m v14, m v15, m v16, m v17, m v18, m v19, m v20) { *v1 = x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12), v13), v14), v15), v16), v17), v18), v19), v20); }
inline void xorEq_20(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12, m v13, m v14, m v15, m v16, m v17, m v18, m v19, m v20, m v21) { *v1 = x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12), v13), v14), v15), v16), v17), v18), v19), v20), v21); }
inline void xorEq_21(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12, m v13, m v14, m v15, m v16, m v17, m v18, m v19, m v20, m v21, m v22) { *v1 = x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12), v13), v14), v15), v16), v17), v18), v19), v20), v21), v22); }
inline void xorEq_22(m* v1, m v2, m v3, m v4, m v5, m v6, m v7, m v8, m v9, m v10, m v11, m v12, m v13, m v14, m v15, m v16, m v17, m v18, m v19, m v20, m v21, m v22, m v23) { *v1 = x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(x(*v1, v2), v3), v4), v5), v6), v7), v8), v9), v10), v11), v12), v13), v14), v15), v16), v17), v18), v19), v20), v21), v22), v23); }

#define xorEq(v1, ...) BOOST_PP_CAT(xorEq_, BOOST_PP_VARIADIC_SIZE(__VA_ARGS__))(&v1, __VA_ARGS__)

#undef m
#undef x

#endif