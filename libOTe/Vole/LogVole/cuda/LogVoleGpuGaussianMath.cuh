#pragma once
// Logarithm constants and polynomial structure adapted from Arm optimized-routines
// math/log.c and math/log_data.c, https://github.com/ARM-software/optimized-routines.
// Copyright (c) 2018-2025, Arm Limited. Selected license: MIT.
// Explicit rounding reproduces the supported glibc FMA implementation's operation order.
/*
Copyright (c) 1999-2022, Arm Limited.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/
#include <cmath>
#include <cstdint>
#if defined(__CUDACC__)
#define LV_GAUSS_HD __host__ __device__
#else
#define LV_GAUSS_HD
#endif
namespace osuCrypto::LogVole::gpu::gaussian_math
{
static constexpr double near_host[] = {
-0x1p-1,
0x1.5555555555577p-2,
-0x1.ffffffffffdcbp-3,
0x1.999999995dd0cp-3,
-0x1.55555556745a7p-3,
0x1.24924a344de3p-3,
-0x1.fffffa4423d65p-4,
0x1.c7184282ad6cap-4,
-0x1.999eb43b068ffp-4,
0x1.78182f7afd085p-4,
-0x1.5521375d145cdp-4,
};
#if defined(__CUDACC__)
static __device__ __constant__ double near_device[] = {
-0x1p-1,
0x1.5555555555577p-2,
-0x1.ffffffffffdcbp-3,
0x1.999999995dd0cp-3,
-0x1.55555556745a7p-3,
0x1.24924a344de3p-3,
-0x1.fffffa4423d65p-4,
0x1.c7184282ad6cap-4,
-0x1.999eb43b068ffp-4,
0x1.78182f7afd085p-4,
-0x1.5521375d145cdp-4,
};
#endif
static constexpr double poly_host[] = {
-0x1.0000000000001p-1,
0x1.555555551305bp-2,
-0x1.fffffffeb459p-3,
0x1.999b324f10111p-3,
-0x1.55575e506c89fp-3,
};
#if defined(__CUDACC__)
static __device__ __constant__ double poly_device[] = {
-0x1.0000000000001p-1,
0x1.555555551305bp-2,
-0x1.fffffffeb459p-3,
0x1.999b324f10111p-3,
-0x1.55575e506c89fp-3,
};
#endif
static constexpr double table_host[][2] = {
{0x1.734f0c3e0de9fp+0, -0x1.7cc7f79e69000p-2},
{0x1.713786a2ce91fp+0, -0x1.76feec20d0000p-2},
{0x1.6f26008fab5a0p+0, -0x1.713e31351e000p-2},
{0x1.6d1a61f138c7dp+0, -0x1.6b85b38287800p-2},
{0x1.6b1490bc5b4d1p+0, -0x1.65d5590807800p-2},
{0x1.69147332f0cbap+0, -0x1.602d076180000p-2},
{0x1.6719f18224223p+0, -0x1.5a8ca86909000p-2},
{0x1.6524f99a51ed9p+0, -0x1.54f4356035000p-2},
{0x1.63356aa8f24c4p+0, -0x1.4f637c36b4000p-2},
{0x1.614b36b9ddc14p+0, -0x1.49da7fda85000p-2},
{0x1.5f66452c65c4cp+0, -0x1.445923989a800p-2},
{0x1.5d867b5912c4fp+0, -0x1.3edf439b0b800p-2},
{0x1.5babccb5b90dep+0, -0x1.396ce448f7000p-2},
{0x1.59d61f2d91a78p+0, -0x1.3401e17bda000p-2},
{0x1.5805612465687p+0, -0x1.2e9e2ef468000p-2},
{0x1.56397cee76bd3p+0, -0x1.2941b3830e000p-2},
{0x1.54725e2a77f93p+0, -0x1.23ec58cda8800p-2},
{0x1.52aff42064583p+0, -0x1.1e9e129279000p-2},
{0x1.50f22dbb2bddfp+0, -0x1.1956d2b48f800p-2},
{0x1.4f38f4734ded7p+0, -0x1.141679ab9f800p-2},
{0x1.4d843cfde2840p+0, -0x1.0edd094ef9800p-2},
{0x1.4bd3ec078a3c8p+0, -0x1.09aa518db1000p-2},
{0x1.4a27fc3e0258ap+0, -0x1.047e65263b800p-2},
{0x1.4880524d48434p+0, -0x1.feb224586f000p-3},
{0x1.46dce1b192d0bp+0, -0x1.f474a7517b000p-3},
{0x1.453d9d3391854p+0, -0x1.ea4443d103000p-3},
{0x1.43a2744b4845ap+0, -0x1.e020d44e9b000p-3},
{0x1.420b54115f8fbp+0, -0x1.d60a22977f000p-3},
{0x1.40782da3ef4b1p+0, -0x1.cc00104959000p-3},
{0x1.3ee8f5d57fe8fp+0, -0x1.c202956891000p-3},
{0x1.3d5d9a00b4ce9p+0, -0x1.b81178d811000p-3},
{0x1.3bd60c010c12bp+0, -0x1.ae2c9ccd3d000p-3},
{0x1.3a5242b75dab8p+0, -0x1.a45402e129000p-3},
{0x1.38d22cd9fd002p+0, -0x1.9a877681df000p-3},
{0x1.3755bc5847a1cp+0, -0x1.90c6d69483000p-3},
{0x1.35dce49ad36e2p+0, -0x1.87120a645c000p-3},
{0x1.34679984dd440p+0, -0x1.7d68fb4143000p-3},
{0x1.32f5cceffcb24p+0, -0x1.73cb83c627000p-3},
{0x1.3187775a10d49p+0, -0x1.6a39a9b376000p-3},
{0x1.301c8373e3990p+0, -0x1.60b3154b7a000p-3},
{0x1.2eb4ebb95f841p+0, -0x1.5737d76243000p-3},
{0x1.2d50a0219a9d1p+0, -0x1.4dc7b8fc23000p-3},
{0x1.2bef9a8b7fd2ap+0, -0x1.4462c51d20000p-3},
{0x1.2a91c7a0c1babp+0, -0x1.3b08abc830000p-3},
{0x1.293726014b530p+0, -0x1.31b996b490000p-3},
{0x1.27dfa5757a1f5p+0, -0x1.2875490a44000p-3},
{0x1.268b39b1d3bbfp+0, -0x1.1f3b9f879a000p-3},
{0x1.2539d838ff5bdp+0, -0x1.160c8252ca000p-3},
{0x1.23eb7aac9083bp+0, -0x1.0ce7f57f72000p-3},
{0x1.22a012ba940b6p+0, -0x1.03cdc49fea000p-3},
{0x1.2157996cc4132p+0, -0x1.f57bdbc4b8000p-4},
{0x1.201201dd2fc9bp+0, -0x1.e370896404000p-4},
{0x1.1ecf4494d480bp+0, -0x1.d17983ef94000p-4},
{0x1.1d8f5528f6569p+0, -0x1.bf9674ed8a000p-4},
{0x1.1c52311577e7cp+0, -0x1.adc79202f6000p-4},
{0x1.1b17c74cb26e9p+0, -0x1.9c0c3e7288000p-4},
{0x1.19e010c2c1ab6p+0, -0x1.8a646b372c000p-4},
{0x1.18ab07bb670bdp+0, -0x1.78d01b3ac0000p-4},
{0x1.1778a25efbcb6p+0, -0x1.674f145380000p-4},
{0x1.1648d354c31dap+0, -0x1.55e0e6d878000p-4},
{0x1.151b990275fddp+0, -0x1.4485cdea1e000p-4},
{0x1.13f0ea432d24cp+0, -0x1.333d94d6aa000p-4},
{0x1.12c8b7210f9dap+0, -0x1.22079f8c56000p-4},
{0x1.11a3028ecb531p+0, -0x1.10e4698622000p-4},
{0x1.107fbda8434afp+0, -0x1.ffa6c6ad20000p-5},
{0x1.0f5ee0f4e6bb3p+0, -0x1.dda8d4a774000p-5},
{0x1.0e4065d2a9fcep+0, -0x1.bbcece4850000p-5},
{0x1.0d244632ca521p+0, -0x1.9a1894012c000p-5},
{0x1.0c0a77ce2981ap+0, -0x1.788583302c000p-5},
{0x1.0af2f83c636d1p+0, -0x1.5715e67d68000p-5},
{0x1.09ddb98a01339p+0, -0x1.35c8a49658000p-5},
{0x1.08cabaf52e7dfp+0, -0x1.149e364154000p-5},
{0x1.07b9f2f4e28fbp+0, -0x1.e72c082eb8000p-6},
{0x1.06ab58c358f19p+0, -0x1.a55f152528000p-6},
{0x1.059eea5ecf92cp+0, -0x1.63d62cf818000p-6},
{0x1.04949cdd12c90p+0, -0x1.228fb8caa0000p-6},
{0x1.038c6c6f0ada9p+0, -0x1.c317b20f90000p-7},
{0x1.02865137932a9p+0, -0x1.419355daa0000p-7},
{0x1.0182427ea7348p+0, -0x1.81203c2ec0000p-8},
{0x1.008040614b195p+0, -0x1.0040979240000p-9},
{0x1.fe01ff726fa1ap-1, 0x1.feff384900000p-9},
{0x1.fa11cc261ea74p-1, 0x1.7dc41353d0000p-7},
{0x1.f6310b081992ep-1, 0x1.3cea3c4c28000p-6},
{0x1.f25f63ceeadcdp-1, 0x1.b9fc114890000p-6},
{0x1.ee9c8039113e7p-1, 0x1.1b0d8ce110000p-5},
{0x1.eae8078cbb1abp-1, 0x1.58a5bd001c000p-5},
{0x1.e741aa29d0c9bp-1, 0x1.95c8340d88000p-5},
{0x1.e3a91830a99b5p-1, 0x1.d276aef578000p-5},
{0x1.e01e009609a56p-1, 0x1.07598e598c000p-4},
{0x1.dca01e577bb98p-1, 0x1.253f5e30d2000p-4},
{0x1.d92f20b7c9103p-1, 0x1.42edd8b380000p-4},
{0x1.d5cac66fb5ccep-1, 0x1.606598757c000p-4},
{0x1.d272caa5ede9dp-1, 0x1.7da76356a0000p-4},
{0x1.cf26e3e6b2ccdp-1, 0x1.9ab434e1c6000p-4},
{0x1.cbe6da2a77902p-1, 0x1.b78c7bb0d6000p-4},
{0x1.c8b266d37086dp-1, 0x1.d431332e72000p-4},
{0x1.c5894bd5d5804p-1, 0x1.f0a3171de6000p-4},
{0x1.c26b533bb9f8cp-1, 0x1.067152b914000p-3},
{0x1.bf583eeece73fp-1, 0x1.147858292b000p-3},
{0x1.bc4fd75db96c1p-1, 0x1.2266ecdca3000p-3},
{0x1.b951e0c864a28p-1, 0x1.303d7a6c55000p-3},
{0x1.b65e2c5ef3e2cp-1, 0x1.3dfc33c331000p-3},
{0x1.b374867c9888bp-1, 0x1.4ba366b7a8000p-3},
{0x1.b094b211d304ap-1, 0x1.5933928d1f000p-3},
{0x1.adbe885f2ef7ep-1, 0x1.66acd2418f000p-3},
{0x1.aaf1d31603da2p-1, 0x1.740f8ec669000p-3},
{0x1.a82e63fd358a7p-1, 0x1.815c0f51af000p-3},
{0x1.a5740ef09738bp-1, 0x1.8e92954f68000p-3},
{0x1.a2c2a90ab4b27p-1, 0x1.9bb3602f84000p-3},
{0x1.a01a01393f2d1p-1, 0x1.a8bed1c2c0000p-3},
{0x1.9d79f24db3c1bp-1, 0x1.b5b515c01d000p-3},
{0x1.9ae2505c7b190p-1, 0x1.c2967ccbcc000p-3},
{0x1.9852ef297ce2fp-1, 0x1.cf635d5486000p-3},
{0x1.95cbaeea44b75p-1, 0x1.dc1bd3446c000p-3},
{0x1.934c69de74838p-1, 0x1.e8c01b8cfe000p-3},
{0x1.90d4f2f6752e6p-1, 0x1.f5509c0179000p-3},
{0x1.8e6528effd79dp-1, 0x1.00e6c121fb800p-2},
{0x1.8bfce9fcc007cp-1, 0x1.071b80e93d000p-2},
{0x1.899c0dabec30ep-1, 0x1.0d46b9e867000p-2},
{0x1.87427aa2317fbp-1, 0x1.13687334bd000p-2},
{0x1.84f00acb39a08p-1, 0x1.1980d67234800p-2},
{0x1.82a49e8653e55p-1, 0x1.1f8ffe0cc8000p-2},
{0x1.8060195f40260p-1, 0x1.2595fd7636800p-2},
{0x1.7e22563e0a329p-1, 0x1.2b9300914a800p-2},
{0x1.7beb377dcb5adp-1, 0x1.3187210436000p-2},
{0x1.79baa679725c2p-1, 0x1.377266dec1800p-2},
{0x1.77907f2170657p-1, 0x1.3d54ffbaf3000p-2},
{0x1.756cadbd6130cp-1, 0x1.432eee32fe000p-2},
};
#if defined(__CUDACC__)
static __device__ __constant__ double table_device[][2] = {
{0x1.734f0c3e0de9fp+0, -0x1.7cc7f79e69000p-2},
{0x1.713786a2ce91fp+0, -0x1.76feec20d0000p-2},
{0x1.6f26008fab5a0p+0, -0x1.713e31351e000p-2},
{0x1.6d1a61f138c7dp+0, -0x1.6b85b38287800p-2},
{0x1.6b1490bc5b4d1p+0, -0x1.65d5590807800p-2},
{0x1.69147332f0cbap+0, -0x1.602d076180000p-2},
{0x1.6719f18224223p+0, -0x1.5a8ca86909000p-2},
{0x1.6524f99a51ed9p+0, -0x1.54f4356035000p-2},
{0x1.63356aa8f24c4p+0, -0x1.4f637c36b4000p-2},
{0x1.614b36b9ddc14p+0, -0x1.49da7fda85000p-2},
{0x1.5f66452c65c4cp+0, -0x1.445923989a800p-2},
{0x1.5d867b5912c4fp+0, -0x1.3edf439b0b800p-2},
{0x1.5babccb5b90dep+0, -0x1.396ce448f7000p-2},
{0x1.59d61f2d91a78p+0, -0x1.3401e17bda000p-2},
{0x1.5805612465687p+0, -0x1.2e9e2ef468000p-2},
{0x1.56397cee76bd3p+0, -0x1.2941b3830e000p-2},
{0x1.54725e2a77f93p+0, -0x1.23ec58cda8800p-2},
{0x1.52aff42064583p+0, -0x1.1e9e129279000p-2},
{0x1.50f22dbb2bddfp+0, -0x1.1956d2b48f800p-2},
{0x1.4f38f4734ded7p+0, -0x1.141679ab9f800p-2},
{0x1.4d843cfde2840p+0, -0x1.0edd094ef9800p-2},
{0x1.4bd3ec078a3c8p+0, -0x1.09aa518db1000p-2},
{0x1.4a27fc3e0258ap+0, -0x1.047e65263b800p-2},
{0x1.4880524d48434p+0, -0x1.feb224586f000p-3},
{0x1.46dce1b192d0bp+0, -0x1.f474a7517b000p-3},
{0x1.453d9d3391854p+0, -0x1.ea4443d103000p-3},
{0x1.43a2744b4845ap+0, -0x1.e020d44e9b000p-3},
{0x1.420b54115f8fbp+0, -0x1.d60a22977f000p-3},
{0x1.40782da3ef4b1p+0, -0x1.cc00104959000p-3},
{0x1.3ee8f5d57fe8fp+0, -0x1.c202956891000p-3},
{0x1.3d5d9a00b4ce9p+0, -0x1.b81178d811000p-3},
{0x1.3bd60c010c12bp+0, -0x1.ae2c9ccd3d000p-3},
{0x1.3a5242b75dab8p+0, -0x1.a45402e129000p-3},
{0x1.38d22cd9fd002p+0, -0x1.9a877681df000p-3},
{0x1.3755bc5847a1cp+0, -0x1.90c6d69483000p-3},
{0x1.35dce49ad36e2p+0, -0x1.87120a645c000p-3},
{0x1.34679984dd440p+0, -0x1.7d68fb4143000p-3},
{0x1.32f5cceffcb24p+0, -0x1.73cb83c627000p-3},
{0x1.3187775a10d49p+0, -0x1.6a39a9b376000p-3},
{0x1.301c8373e3990p+0, -0x1.60b3154b7a000p-3},
{0x1.2eb4ebb95f841p+0, -0x1.5737d76243000p-3},
{0x1.2d50a0219a9d1p+0, -0x1.4dc7b8fc23000p-3},
{0x1.2bef9a8b7fd2ap+0, -0x1.4462c51d20000p-3},
{0x1.2a91c7a0c1babp+0, -0x1.3b08abc830000p-3},
{0x1.293726014b530p+0, -0x1.31b996b490000p-3},
{0x1.27dfa5757a1f5p+0, -0x1.2875490a44000p-3},
{0x1.268b39b1d3bbfp+0, -0x1.1f3b9f879a000p-3},
{0x1.2539d838ff5bdp+0, -0x1.160c8252ca000p-3},
{0x1.23eb7aac9083bp+0, -0x1.0ce7f57f72000p-3},
{0x1.22a012ba940b6p+0, -0x1.03cdc49fea000p-3},
{0x1.2157996cc4132p+0, -0x1.f57bdbc4b8000p-4},
{0x1.201201dd2fc9bp+0, -0x1.e370896404000p-4},
{0x1.1ecf4494d480bp+0, -0x1.d17983ef94000p-4},
{0x1.1d8f5528f6569p+0, -0x1.bf9674ed8a000p-4},
{0x1.1c52311577e7cp+0, -0x1.adc79202f6000p-4},
{0x1.1b17c74cb26e9p+0, -0x1.9c0c3e7288000p-4},
{0x1.19e010c2c1ab6p+0, -0x1.8a646b372c000p-4},
{0x1.18ab07bb670bdp+0, -0x1.78d01b3ac0000p-4},
{0x1.1778a25efbcb6p+0, -0x1.674f145380000p-4},
{0x1.1648d354c31dap+0, -0x1.55e0e6d878000p-4},
{0x1.151b990275fddp+0, -0x1.4485cdea1e000p-4},
{0x1.13f0ea432d24cp+0, -0x1.333d94d6aa000p-4},
{0x1.12c8b7210f9dap+0, -0x1.22079f8c56000p-4},
{0x1.11a3028ecb531p+0, -0x1.10e4698622000p-4},
{0x1.107fbda8434afp+0, -0x1.ffa6c6ad20000p-5},
{0x1.0f5ee0f4e6bb3p+0, -0x1.dda8d4a774000p-5},
{0x1.0e4065d2a9fcep+0, -0x1.bbcece4850000p-5},
{0x1.0d244632ca521p+0, -0x1.9a1894012c000p-5},
{0x1.0c0a77ce2981ap+0, -0x1.788583302c000p-5},
{0x1.0af2f83c636d1p+0, -0x1.5715e67d68000p-5},
{0x1.09ddb98a01339p+0, -0x1.35c8a49658000p-5},
{0x1.08cabaf52e7dfp+0, -0x1.149e364154000p-5},
{0x1.07b9f2f4e28fbp+0, -0x1.e72c082eb8000p-6},
{0x1.06ab58c358f19p+0, -0x1.a55f152528000p-6},
{0x1.059eea5ecf92cp+0, -0x1.63d62cf818000p-6},
{0x1.04949cdd12c90p+0, -0x1.228fb8caa0000p-6},
{0x1.038c6c6f0ada9p+0, -0x1.c317b20f90000p-7},
{0x1.02865137932a9p+0, -0x1.419355daa0000p-7},
{0x1.0182427ea7348p+0, -0x1.81203c2ec0000p-8},
{0x1.008040614b195p+0, -0x1.0040979240000p-9},
{0x1.fe01ff726fa1ap-1, 0x1.feff384900000p-9},
{0x1.fa11cc261ea74p-1, 0x1.7dc41353d0000p-7},
{0x1.f6310b081992ep-1, 0x1.3cea3c4c28000p-6},
{0x1.f25f63ceeadcdp-1, 0x1.b9fc114890000p-6},
{0x1.ee9c8039113e7p-1, 0x1.1b0d8ce110000p-5},
{0x1.eae8078cbb1abp-1, 0x1.58a5bd001c000p-5},
{0x1.e741aa29d0c9bp-1, 0x1.95c8340d88000p-5},
{0x1.e3a91830a99b5p-1, 0x1.d276aef578000p-5},
{0x1.e01e009609a56p-1, 0x1.07598e598c000p-4},
{0x1.dca01e577bb98p-1, 0x1.253f5e30d2000p-4},
{0x1.d92f20b7c9103p-1, 0x1.42edd8b380000p-4},
{0x1.d5cac66fb5ccep-1, 0x1.606598757c000p-4},
{0x1.d272caa5ede9dp-1, 0x1.7da76356a0000p-4},
{0x1.cf26e3e6b2ccdp-1, 0x1.9ab434e1c6000p-4},
{0x1.cbe6da2a77902p-1, 0x1.b78c7bb0d6000p-4},
{0x1.c8b266d37086dp-1, 0x1.d431332e72000p-4},
{0x1.c5894bd5d5804p-1, 0x1.f0a3171de6000p-4},
{0x1.c26b533bb9f8cp-1, 0x1.067152b914000p-3},
{0x1.bf583eeece73fp-1, 0x1.147858292b000p-3},
{0x1.bc4fd75db96c1p-1, 0x1.2266ecdca3000p-3},
{0x1.b951e0c864a28p-1, 0x1.303d7a6c55000p-3},
{0x1.b65e2c5ef3e2cp-1, 0x1.3dfc33c331000p-3},
{0x1.b374867c9888bp-1, 0x1.4ba366b7a8000p-3},
{0x1.b094b211d304ap-1, 0x1.5933928d1f000p-3},
{0x1.adbe885f2ef7ep-1, 0x1.66acd2418f000p-3},
{0x1.aaf1d31603da2p-1, 0x1.740f8ec669000p-3},
{0x1.a82e63fd358a7p-1, 0x1.815c0f51af000p-3},
{0x1.a5740ef09738bp-1, 0x1.8e92954f68000p-3},
{0x1.a2c2a90ab4b27p-1, 0x1.9bb3602f84000p-3},
{0x1.a01a01393f2d1p-1, 0x1.a8bed1c2c0000p-3},
{0x1.9d79f24db3c1bp-1, 0x1.b5b515c01d000p-3},
{0x1.9ae2505c7b190p-1, 0x1.c2967ccbcc000p-3},
{0x1.9852ef297ce2fp-1, 0x1.cf635d5486000p-3},
{0x1.95cbaeea44b75p-1, 0x1.dc1bd3446c000p-3},
{0x1.934c69de74838p-1, 0x1.e8c01b8cfe000p-3},
{0x1.90d4f2f6752e6p-1, 0x1.f5509c0179000p-3},
{0x1.8e6528effd79dp-1, 0x1.00e6c121fb800p-2},
{0x1.8bfce9fcc007cp-1, 0x1.071b80e93d000p-2},
{0x1.899c0dabec30ep-1, 0x1.0d46b9e867000p-2},
{0x1.87427aa2317fbp-1, 0x1.13687334bd000p-2},
{0x1.84f00acb39a08p-1, 0x1.1980d67234800p-2},
{0x1.82a49e8653e55p-1, 0x1.1f8ffe0cc8000p-2},
{0x1.8060195f40260p-1, 0x1.2595fd7636800p-2},
{0x1.7e22563e0a329p-1, 0x1.2b9300914a800p-2},
{0x1.7beb377dcb5adp-1, 0x1.3187210436000p-2},
{0x1.79baa679725c2p-1, 0x1.377266dec1800p-2},
{0x1.77907f2170657p-1, 0x1.3d54ffbaf3000p-2},
{0x1.756cadbd6130cp-1, 0x1.432eee32fe000p-2},
};
#endif
LV_GAUSS_HD inline double near(unsigned i) {
#if defined(__CUDA_ARCH__)
 return near_device[i];
#else
 return near_host[i];
#endif
}
LV_GAUSS_HD inline double poly(unsigned i) {
#if defined(__CUDA_ARCH__)
 return poly_device[i];
#else
 return poly_host[i];
#endif
}
LV_GAUSS_HD inline double table(unsigned i, unsigned j) {
#if defined(__CUDA_ARCH__)
 return table_device[i][j];
#else
 return table_host[i][j];
#endif
}
LV_GAUSS_HD inline double add(double a, double b) {
#if defined(__CUDA_ARCH__)
 return __dadd_rn(a,b);
#else
 volatile double r=a+b; return r;
#endif
}
LV_GAUSS_HD inline double sub(double a, double b) {
#if defined(__CUDA_ARCH__)
 return __dsub_rn(a,b);
#else
 volatile double r=a-b; return r;
#endif
}
LV_GAUSS_HD inline double mul(double a, double b) {
#if defined(__CUDA_ARCH__)
 return __dmul_rn(a,b);
#else
 volatile double r=a*b; return r;
#endif
}
LV_GAUSS_HD inline double div(double a, double b) {
#if defined(__CUDA_ARCH__)
 return __ddiv_rn(a,b);
#else
 volatile double r=a/b; return r;
#endif
}
LV_GAUSS_HD inline double fma(double a, double b, double c) {
#if defined(__CUDA_ARCH__)
 return __fma_rn(a,b,c);
#else
 return std::fma(a,b,c);
#endif
}
LV_GAUSS_HD inline double sqrt(double a) {
#if defined(__CUDA_ARCH__)
 return __dsqrt_rn(a);
#else
 return std::sqrt(a);
#endif
}
LV_GAUSS_HD inline std::uint64_t bits(double value) {
 union { double d; std::uint64_t u; } v; v.d=value; return v.u;
}
LV_GAUSS_HD inline double from_bits(std::uint64_t value) {
 union { double d; std::uint64_t u; } v; v.u=value; return v.d;
}
// Only positive normal inputs are used by the polar sampler. It operates on
// doubles derived from 64 random bits, so any positive radius is >= 2^-106.
LV_GAUSS_HD inline double log(double x)
{
 const auto ix=bits(x);
 if (ix - 0x3fee000000000000ULL < 0x3090000000000ULL) {
  if(ix == 0x3ff0000000000000ULL) return 0.0;
  const double r=sub(x,1.0), r2=mul(r,r), r3=mul(r,r2);
  double p=fma(r,near(2),near(1));
  double q=fma(r,near(5),near(4));
  double t=fma(r,near(8),near(7));
  p=fma(r2,near(3),p); q=fma(r2,near(6),q);
  t=fma(r2,near(9),t); t=fma(r3,near(10),t);
  t=fma(r3,t,q); t=fma(r3,t,p);
  const double rhi=fma(-r,0x1p27,fma(r,0x1p27,r));
  const double rlo=sub(r,rhi), rhisq=mul(rhi,rhi);
  const double hi=fma(rhisq,near(0),r);
  double lo=fma(rhisq,near(0),sub(r,hi));
  lo=fma(mul(near(0),rlo),add(r,rhi),lo);
  return add(hi,fma(r3,t,lo));
 }
 const std::uint64_t tmp=ix-0x3fe6000000000000ULL;
 const unsigned i=(tmp>>45)&127;
 const int k=static_cast<std::int64_t>(tmp)>>52;
 const double z=from_bits(ix-(tmp&0xfff0000000000000ULL));
 const double r=fma(z,table(i,0),-1.0);
 const double w=fma(static_cast<double>(k),0x1.62e42fefa3800p-1,table(i,1));
 const double hi=add(r,w), r2=mul(r,r), r3=mul(r,r2);
 double lo=add(sub(w,hi),r);
 lo=fma(static_cast<double>(k),0x1.ef35793c76730p-45,lo);
 lo=fma(r2,poly(0),lo);
 const double p=fma(r,poly(2),poly(1));
 const double q=fma(r,poly(4),poly(3));
 return add(fma(r3,fma(r2,q,p),lo),hi);
}
LV_GAUSS_HD inline double uniform(std::uint32_t lo, std::uint32_t hi)
{
 double u=mul(fma(static_cast<double>(hi),0x1p32,static_cast<double>(lo)),0x1p-64);
 return u>=1.0 ? 0x1.fffffffffffffp-1 : u;
}
LV_GAUSS_HD inline void pair(const std::uint32_t* words, double& x, double& y, double& radius)
{
 x=fma(2.0,uniform(words[0],words[1]),-1.0);
 y=fma(2.0,uniform(words[2],words[3]),-1.0);
 radius=fma(y,y,mul(x,x));
}
LV_GAUSS_HD inline double scaled(double v, double multiplier, double sigma)
{ return fma(mul(v,multiplier),sigma,0.0); }
}
#undef LV_GAUSS_HD
