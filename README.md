
![](./titleOSU.PNG)
=====

![Build Status](https://github.com/osu-crypto/libOTe/actions/workflows/build-test.yml/badge.svg)

A fast and portable C++17 library for Oblivious Transfer extension (OTe). The 
primary design goal of this library to obtain *high performance* while being 
*easy to use*. Checkout [version 1.6](https://github.com/osu-crypto/libOTe/releases/tag/v1.6.0) for the previous version.
 
Semi-honest OT extension:
* 1-out-of-2 Silent OT [[BCGIKRS19]](https://eprint.iacr.org/2019/1159.pdf),[[RRT23]](https://eprint.iacr.org/2023/882).
* 1-out-of-2 OT [[IKNP03]](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf).
* 1-out-of-2 Correlated-OT [[IKNP03]](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf),[[BLNNOOSS15]](https://eprint.iacr.org/2015/472.pdf).
* 1-out-of-2 OT [[Roy22]](https://eprint.iacr.org/2022/192).
* 1-out-of-N OT [[KKRT16]](https://eprint.iacr.org/2016/799). 

Malicious OT extension:
* 1-out-of-2 Silent OT [[BCGIKRS19]](https://eprint.iacr.org/2019/1159.pdf),[[RRT23]](https://eprint.iacr.org/2023/882).
* 1-out-of-2 OT [[KOS15]](https://eprint.iacr.org/2015/546).
* 1-out-of-2 Correlated-OT [[KOS15]](https://eprint.iacr.org/2015/546).
* 1-out-of-2 OT [[Roy22]](https://eprint.iacr.org/2022/192).
* 1-out-of-2 base OT, several protocols. 

Vole:
* Generic subfield noisy VOLE (semi-honest) [[BCGIKRS19]](https://eprint.iacr.org/2019/1159.pdf)
* Generic subfield silent VOLE (malicious/semi-honest)  [[BCGIKRS19]](https://eprint.iacr.org/2019/1159.pdf),[[RRT23]](https://eprint.iacr.org/2023/882).
 
## Introduction
 
This library provides several different classes of OT protocols. First is the 
base OT protocol of [CO15, MR19, MRR21]. These protocol bootstraps all the other
OT extension protocols.  Within the OT extension protocols, we have 1-out-of-2,
1-out-of-N, and VOLE both in the semi-honest and malicious settings. See The `frontend` or `libOTe_Tests` folder for examples.

All implementations are highly optimized using fast SSE instructions and vectorization
to obtain optimal performance both in the single and multi-threaded setting. 
 
Networking can be performed using both the sockets provided by the library and
external socket classes. The simplest integration can be achieved via the [message passing interface](https://github.com/osu-crypto/libOTe/blob/master/frontend/ExampleMessagePassing.h) where the user is given the protocol messages that need to be sent/received. Users can also integrate their own socket type for maximum performance. See the [coproto](https://github.com/Visa-Research/coproto/blob/main/frontend/SocketTutorial.cpp) tutorial for examples.


## Build
 
The library is *cross platform* and has been tested on Windows, Mac and Linux. 
There is one mandatory dependency on [coproto](https://github.com/Visa-Research/coproto) (networking),
and three **optional dependencies** on [libsodium](https://doc.libsodium.org/),
[Relic](https://github.com/relic-toolkit/relic), or
[SimplestOT](https://github.com/osu-crypto/libOTe/tree/master/SimplestOT) (Unix only)
for Base OTs. [Boost Asio](https://www.boost.org/doc/libs/1_77_0/doc/html/boost_asio.html) tcp networking and [OpenSSL](https://www.openssl.org/) support can optionally be enabled.
CMake 3.15+ is required and the build script assumes python 3.
 
The library can be built with libsodium, all OT protocols enabled and boost asio TCP networking as
```
git clone https://github.com/osu-crypto/libOTe.git
cd libOTe
python build.py --all --boost --sodium
```
The main executable with examples is `frontend` and is located in the build directory, eg `out/build/linux/frontend/frontend.exe, out/build/x64-Release/frontend/Release/frontend.exe` depending on the OS. 

### Build Options
LibOTe can be built with various only the selected protocols enabled. `-D ENABLE_ALL_OT=ON` will enable all available protocols depending on platform/dependencies. The `ON`/`OFF` options include

**Malicious base OT:**
 * `ENABLE_SIMPLESTOT` the SimplestOT [[CO15]](https://eprint.iacr.org/2015/267.pdf) protocol (relic or sodium).
 * `ENABLE_SIMPLESTOT_ASM` the SimplestOT base OT protocol [[CO15]](https://eprint.iacr.org/2015/267.pdf) protocol (linux assembly).
 * `ENABLE_MRR` the McQuoid Rosulek Roy [[MRR20]](https://eprint.iacr.org/2020/1043) protocol (relic or sodium).
 * `ENABLE_MRR_TWIST` the McQuoid Rosulek Roy [[MRR21]](https://eprint.iacr.org/2021/682) protocol  (sodium fork).
 * `ENABLE_MR` the Masny Rindal [[MR19]](https://eprint.iacr.org/2019/706.pdf) protocol (relic or sodium).
 * `ENABLE_MR_KYBER` the Masny Rindal [[MR19]](https://eprint.iacr.org/2019/706.pdf) protocol  (Kyber fork).
 * `ENABLE_NP` the Naor Pinkas [NP01] base OT (relic or sodium).

**1-out-of-2 OT Extension:**
 * `ENABLE_IKNP` the Ishai et al [[IKNP03]](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf) semi-honest protocol.
 * `ENABLE_KOS` the Keller et al [[KOS15]](https://eprint.iacr.org/2015/546) malicious protocol.
 * `ENABLE_DELTA_KOS` the Burra et al [[BLNNOOSS15]](https://eprint.iacr.org/2015/472.pdf),[[KOS15]](https://eprint.iacr.org/2015/546) malicious Delta-OT protocol.
 * `ENABLE_SOFTSPOKEN_OT` the Roy [Roy22](https://eprint.iacr.org/2022/192) semi-honest/malicious protocol.
 * `ENABLE_SILENTOT` the [[BCGIKRS19]](https://eprint.iacr.org/2019/1159.pdf),[[RRT23]](https://eprint.iacr.org/2023/882) semi-honest/malicious protocol.

 **Vole:**
 * `ENABLE_SILENT_VOLE` the [[BCGIKRS19]](https://eprint.iacr.org/2019/1159.pdf),[[RRT23]](https://eprint.iacr.org/2023/882) semi-honest/malicious protocol.

 Addition options can be set for cryptoTools. See the cmake output.

### Dependencies

Dependencies can be managed by cmake/build.py or installed via an external tool. If an external tool is used install to system location or set  `-D CMAKE_PREFIX_PATH=path/to/install`. By default `build.py` calls cmake with the command line argument
```
-D FETCH_AUTO=true
```
. This tells cmake to first look for dependencies on *the system* and if not found then it will be downloaded and built automatically. If set to `false` then the build will fail if not found. Each dependency can downloaded and build for you by explicitly setting it's `FETCH_***` variable to `true`. See blow. The python `build.py` script by default sets `FETCH_AUTO=true` and can be set to `false` by calling it with `--noauto`.


**Enabling/Disabling [Relic](https://github.com/relic-toolkit/relic) (for base OTs):**
 The library can be built with Relic as
```
python build.py --relic
```
Relic can be disabled by removing `--relic` from the setup and setting `-D ENABLE_RELIC=false`. This will always download and build relic. To only enable but not download relic, use `python build.py -D ENABLE_RELIC=true`.

**Enabling/Disabling [libsodium](https://github.com/osu-crypto/libsodium) (for base OTs):**
  The library can be built with libsodium as
```
python build.py --sodium
```
libsodium can be disabled by removing `--sodium` from the setup and setting `-D ENABLE_SODIUM=false`.  This will always download and build sodium. To only enable but not download relic, use `python build.py -D ENABLE_SODIUM=true`.

The McQuoid Rosulek Roy 2021 Base OTs uses a twisted curve which additionally require the `noclamp` option for Montgomery curves and is currently only in a [fork](https://github.com/osu-crypto/libsodium) of libsodium. If you prefer the stable libsodium, then install it and add `-D SODIUM_MONTGOMERY=false` as a cmake argument to libOTe.


**Enabling/Disabling [boost asio](https://www.boost.org/doc/libs/1_77_0/doc/html/boost_asio.html) (for TCP networking):**
  The library can be built with boost as
```
python build.py --boost
```
boost can be disabled by removing `--boost` from the setup and setting `-D ENABLE_BOOST=false`.  This will always download and build boost. To only enable but not download relic, use `python build.py -D ENABLE_BOOST=true`.



**Enabling/Disabling [OpenSSL](https://www.boost.org/doc/libs/1_77_0/doc/html/boost_asio.html) (for TLS networking):**
  The library can be built with boost as
```
python build.py --openssl
```
OpenSSL can be disabled by removing `--openssl` from the setup and setting `-D ENABLE_OPENSSL=false`. OpenSSL is never downloaded for you and is always found using your system installs.

## Install

libOTe can be installed and linked the same way as other cmake projects. To install the library and all downloaded dependencies, run the following
```
python build.py --install
```

Sudo is not used. If installation requires sudo access, then install as root. See `python build.py --help` for full details.


## Linking
libOTe can be linked via cmake as
```
find_package(libOTe REQUIRED)
target_link_libraries(myProject oc::libOTe)
```
Other exposed targets are `oc::cryptoTools, oc::tests_cryptoTools, oc::libOTe_Tests`. In addition, cmake variables `libOTe_LIB, libOTe_INC, ENABLE_XXX` will be defined, where `XXX` is one of the libOTe options.

To ensure that cmake can find libOTe, you can either install libOTe or build it locally and set `-D CMAKE_PREFIX_PATH=path/to/libOTe` or provide its location as a cmake `HINTS`, i.e. `find_package(libOTe HINTS path/to/libOTe)`.

libOTe can be found with the following components:
```
find_package(libOTe REQUIRED 
    COMPONENTS 
        std_14
        std_17
        std_20
        
        Debug
        Release
        RelWithDebInfo

        boost
        relic
        sodium
        bitpolymul
        openssl
        circuits

        sse
        avx
        asan
        pic
        no_sse
        no_avx
        no_asan
        no_pic

        simplestot
        simplestot_asm
        mrr
        mrr_twist
        mr
        mr_kyber
        kos
        iknp
        silentot
        softspoken_ot
        delta_kos
        silent_vole
        oos
        kkrt
)
```

## Help
 
Contact Peter Rindal peterrindal@gmail.com for any assistance on building 
or running the library.

## Citing

 Spread the word!

```
@misc{libOTe,
    author = {Peter Rindal, Lance Roy},
    title = {{libOTe: an efficient, portable, and easy to use Oblivious Transfer Library}},
    howpublished = {\url{https://github.com/osu-crypto/libOTe}},
}
```

## Citation
 
[NP01]   -    Moni Naor, Benny Pinkas, _Efficient Oblivious Transfer Protocols_. 

[IKNP03] - Yuval Ishai and Joe Kilian and Kobbi Nissim and Erez Petrank, _Extending Oblivious Transfers Efficiently_. 
 
[KOS15]  - Marcel Keller and Emmanuela Orsini and Peter Scholl, _Actively Secure OT Extension with Optimal Overhead_. [eprint/2015/546](https://eprint.iacr.org/2015/546)
 
[OOS16]  - Michele Orrù and Emmanuela Orsini and Peter Scholl, _Actively Secure 1-out-of-N OT Extension with Application to Private Set Intersection_. [eprint/2016/933](http://eprint.iacr.org/2016/933)
 
[KKRT16]  - Vladimir Kolesnikov and Ranjit Kumaresan and Mike Rosulek and Ni Trieu, _Efficient Batched Oblivious PRF with Applications to Private Set Intersection_. [eprint/2016/799](https://eprint.iacr.org/2016/799)
 
[RR16]  - Peter Rindal and Mike Rosulek, _Improved Private Set Intersection against Malicious Adversaries_. [eprint/2016/746](https://eprint.iacr.org/2016/746)

[BLNNOOSS15]  - Sai Sheshank Burra and Enrique Larraia and Jesper Buus Nielsen and Peter Sebastian Nordholt and Claudio Orlandi and Emmanuela Orsini and Peter Scholl and Nigel P. Smart, _High Performance Multi-Party Computation for Binary Circuits Based on Oblivious Transfer_. [eprint/2015/472](https://eprint.iacr.org/2015/472.pdf)

[ALSZ15]  - Gilad Asharov and Yehuda Lindell and Thomas Schneider and Michael Zohner, _More Efficient Oblivious Transfer Extensions with Security for Malicious Adversaries_. [eprint/2015/061](https://eprint.iacr.org/2015/061)

[CRR21] - Geoffroy Couteau ,Srinivasan Raghuraman and Peter Rindal, _Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes_.

[Roy22] - Lawrence Roy, SoftSpokenOT: Communication--Computation Tradeoffs in OT Extension. [eprint/2022/192](https://eprint.iacr.org/2022/192)

[RRT23] - Srinivasan Raghuraman, Peter Rindal and  Titouan Tanguy, _Expand-Convolute Codes for Pseudorandom Correlation Generators from LPN_. [eeprint/2023/882](https://eprint.iacr.org/2023/882)
