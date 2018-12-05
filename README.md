# libOTe

[![Build Status](https://travis-ci.org/osu-crypto/libOTe.svg?branch=master)](https://travis-ci.org/osu-crypto/libOTe)

A fast and portable C++11 library for Oblivious Transfer extension (OTe). The primary design goal of this library to obtain *high performance* while being *easy to use*.  This library currently implements:
 
* The semi-honest 1-out-of-2 OT [IKNP03].
* The semi-honest 1-out-of-2 Delta-OT [IKNP03],[[BLNNOOSS15]](https://eprint.iacr.org/2015/472.pdf).
* The semi-honest 1-out-of-N OT [[KKRT16]](https://eprint.iacr.org/2016/799). 
* The malicious secure 1-out-of-2 OT [[KOS15]](https://eprint.iacr.org/2015/546).
* The malicious secure 1-out-of-2 Delta-OT [[KOS15]](https://eprint.iacr.org/2015/546),[[BLNNOOSS15]](https://eprint.iacr.org/2015/472.pdf).
* The malicious secure 1-out-of-N OT [[OOS16]](http://eprint.iacr.org/2016/933).
* The malicious secure approximate K-out-of-N OT [[RR16]](https://eprint.iacr.org/2016/746).
* The malicious secure 1-out-of-2 base OT [NP00].
* The malicious secure 1-out-of-2 base OT [[CO15]](https://eprint.iacr.org/2015/267.pdf) (unix only).
 
## Introduction
 
This library provides several different classes of OT protocols. First is the base OT protocol of Naor Prinkas [NP00]. This protocol bootstraps all the other OT extension protocols.  Within the OT extension protocols, we have 1-out-of-2, 1-out-of-N and ~K-out-of-N, both in the semi-honest and malicious settings.
 
All implementations are highly optimized using fast SSE instructions and vectorization to obtain optimal performance both in the single and multi-threaded setting. See the **Performance** section for a comparison between protocols and to other libraries. 
 
Networking can be performed using both the sockets provided by the library and external socket classes. See the [networking tutorial](https://github.com/ladnir/cryptoTools/blob/57220fc45252d089a7fd90816144e447a2ce02b8/frontend_cryptoTools/Tutorials/Network.cpp#L264) for an example.

## Performance
 
The running time in seconds for computing n=2<sup>24</sup> OTs on a single Intel Xeon server (`2 36-cores Intel Xeon CPU E5-2699 v3 @ 2.30GHz and 256GB of RAM`) as of 11/16/2016. All timings shown reflect a "single" thread per party, with the expection that network IO in libOTe is performed in the background by a separate thread. 
 
 
| *Type*                	| *Security*  	| *Protocol*     	| libOTe (SHA1/AES)	| [Encrypto Group](https://github.com/encryptogroup/OTExtension) (SHA256) 	| [Apricot](https://github.com/bristolcrypto/apricot) (AES-hash)	| OOS16 (blake2)	| [emp-toolkit](https://github.com/emp-toolkit) (AES-hash)	|
|---------------------	|-----------	|--------------	|----------------	|----------------	|---------	|---------	|------------	|
| 1-out-of-N (N=2<sup>76</sup>) | malicious | OOS16    	| **10.6 / 9.2**       	| ~              	| ~     	| 24**     	| ~          	|
| 1-out-of-N (N=2<sup>128</sup>)| passive| KKRT16      	| **9.2 / 6.7**        	| ~              	| ~       	| ~       	| ~          	|
| 1-out-of-2 Delta-OT  	| malicious   	| KOS15       	| **1.9***        		| ~              	| ~     	| ~        	|  ~      	|
| 1-out-of-2 Delta-OT  	| passive   	| KOS15       	| **1.7***        		| ~              	| ~     	| ~        	|  ~      	|
| 1-out-of-2          	| malicious 	| ALSZ15        | ~          	        | 17.3          	| ~       	| ~       	|  10         	|
| 1-out-of-2           	| malicious   	| KOS15       	| **3.9 / 0.7**        	| ~              	| 1.1     	| ~        	|  2.9       	|
| 1-out-of-2          	| passive   	| IKNP03       	| **3.7 / 0.6**        	| 11.3          	| **0.6**   | ~     	|  2.7      	|
| 1-out-of-2 Base      	| malicious   	| CO15       	| **963,584/~**        	| ~              	|~       	| ~        	| ~          	|
| 1-out-of-2 Base     	| malicious   	| NP00       	| **2,011,136/~**        	| ~             	| ~		    | ~     	| ~         	|
 

 
## Install
 
The library is *cross platform* and has been tested on Windows, Mac and Linux. There one mandatory dependency on [Boost](http://www.boost.org/) (networking), and three <b>optional dependencies</b> on
 * [Miracl](https://www.miracl.com/index)
 * [Relic](https://github.com/relic-toolkit/relic/) or 
 * [SimplestOT](https://github.com/osu-crypto/libOTe/tree/master/SimplestOT) 

 for Base OT. Any or all of these dependenies can be enabled. See below. For Boost and Miracl we provide a script that automates the download and build steps. The version of Miracl used by this library requires specific configuration and therefore we advise using the cloned repository that we provide.

 
### Windows

In `Powershell`, this will set up the project (with Miracl)

```
git clone --recursive https://github.com/osu-crypto/libOTe.git
cd libOTe/cryptoTools/thirdparty/win
getBoost.ps1 
getMiracl.ps1  
cd ../../..
libOTe.sln
```

This will allow you to build the library with the <b>Miracl</b> library. If Relic or no base OTs are requered, then `getMiracl.ps1` can be skipped. If Relic is used, use the [visual studio port](https://github.com/ladnir/relic) and have CMake install it to `C:\libs`.

Build the solution within visual studio or with `MSBuild`. To see all the command line options, execute the program 

`frontend.exe` 

<b>Requirements:</b> `Powershell`, Powershell `Set-ExecutionPolicy  Unrestricted`, `Visual Studio 2017`, CPU supporting `PCLMUL`, `AES-NI`, and `SSE4.1`.

<b>Optional:</b> `nasm` for improved SHA1 performance. 

<b>IMPORTANT:</b> By default, the build system needs the NASM compiler to be located at `C:\NASM\nasm.exe`. In the event that it isn't, there are two options, install it, or enable the pure c++ implementation. The latter option is done by excluding `cryptoTools/Crypto/asm/sha_win64.asm` from the build system and defining `NO_INTEL_ASM_SHA1` in `cryptoTools/Common/config.h`.

<b>Boost and visual studio 2017:</b>  If boost does not build with visual studio 2017 follow [these instructions](https://stackoverflow.com/questions/41464356/build-boost-with-msvc-14-1-vs2017-rc). 

<b>Miracl and visual studio 2017:</b> If the Miracl script fails to find visual studio 2017, open the script and manually specify the path. 
 
<b>Empty cryptoTools:</b> If the cryptoTools directory is empty `git submodule update --init --recursive`.

### Linux / Mac
 
 In short, this will build the project (with Miracl)

```
git clone --recursive https://github.com/osu-crypto/libOTe.git
cd libOTe/cryptoTools/thirdparty/linux
bash all.get
cd ../../..
cmake . -DENABLE_MIRACL=ON
make
```

This will allow you to build the library with the <b>Miracl</b> library. Altenatively, if [Relic](https://github.com/relic-toolkit/relic/) is installed you can instead call `cmake . -DENABLE_RELIC=ON`. Finally, if on <b>linux x64</b> the assembly base implementation of [SimplestOT](https://github.com/osu-crypto/libOTe/tree/master/SimplestOT) can be enabled with `cmake . -DENABLE_SIMPLESTOT=ON`.

The libraries will be placed in `libOTe/lib` and the binary `frontend.exe` will be placed in `libOTe/bin` To see all the command line options, execute the program 
 
`./bin/frontend.exe`

<b>Requirements:</b> `CMake`, `Make`, `g++` or similar, CPU supporting `PCLMUL`, `AES-NI`, and `SSE4.1`. Optional: `nasm` for improved RandomOracle performance.

<b>Using Simplest OT:</b> to use the third party library SimplestOT, call `cmake -DEnableSimplestOT=OFF .`

<b>Note:</b> In the case that miracl or boost is already installed, the steps  `cd libOTe/thirdparty/linux; bash all.get` can be skipped and CMake will attempt to find them instead. Boost is found with the CMake findBoost package and miracl is found with the `find_library(miracl)` command.
 


<b>Mac issue:</b> if make reports an error about `nasm: fatal: unrecognised output format 'macho64' - use -hf for a list`, the current version of NASM is out of date. Either update nasm or call 
```
export cryptoTools_NO_NASM=true
```

<b>Empty cryptoTools:</b> If the cryptoTools directory is empty `git submodule update --init --recursive`.

### Linking

 You can either `make install` on linux or link libOTe's source tree. In the latter case, you will need to include the following:
1) .../libOTe
2) .../libOTe/cryptoTools
3) .../libOTe/cryptoTools/thirdparty/linux/boost
4) .../libOTe/cryptoTools/thirdparty/linux/miracl/miracl

and link:
1) .../libOTe/bin/liblibOTe.a
2) .../libOTe/bin/libcryptoTools.a
3) .../libOTe/bin/libSimplestOT.a    <i>(if enabled)</i>
4) .../libOTe/cryptoTools/thirdparty/linux/boost/stage/lib/libboost_system.a
5) .../libOTe/cryptoTools/thirdparty/linux/boost/stage/lib/libboost_thread.a
6) .../libOTe/cryptoTools/thirdparty/linux/miracl/miracl/source/libmiracl.a


<b>Note:</b> On windows the linking paths follow a similar pattern.

## Help
 
Contact Peter Rindal rindalp@oregonstate.edu for any assistance on building or running the library.

## Citing

 Spread the word!

```
@misc{libOTe,
    author = {Peter Rindal},
    title = {{libOTe: an efficient, portable, and easy to use Oblivious Transfer Library}},
    howpublished = {\url{https://github.com/osu-crypto/libOTe}},
}
```

## Protocol Details
The 1-out-of-N [OOS16] protocol currently is set to work forn N=2<sup>76</sup> but is capable of supporting arbitrary codes given the generator matrix in text format. See `./libOTe/Tools/Bch511.txt` for an example.
 
The 1-out-of-N  [KKRT16] for arbitrary N is also implemented and slightly faster than [OOS16]. However, [KKRT16] is in the semi-honest setting.
 
The approximate K-out-of-N OT [RR16] protocol is also implemented. This protocol allows for a rough bound on the value K with a very light weight cut and choose technique. It was introduced for a PSI protocol that builds on a Garbled Bloom Filter.
 
 
\* Delta-OT does not use the RandomOracle or AES hash function.
 
\** This timing was taken from the [[OOS16]](http://eprint.iacr.org/2016/933) paper and their implementation used multiple threads. The number was not specified. When using the libOTe implementation with multiple threads, a timing of 2.6 seconds was obtained with the RandomOracle hash function.
 
It should be noted that the libOTe implementation uses the Boost ASIO library to perform more efficient asynchronous network IO. This involves using a background thread to help process network data. As such, this is not a completely fair comparison to the Apricot implementation but we don't expect it to have a large impact. It also appears that the Encrypto Group implementation uses asynchronous network IO.
 

 The above timings were obtained with the follwoing options:

 1-out-of-2 malicious:
 * Apricot: `./ot.x -n 16777216 -p 0 -m a -l 100 & ./ot.x -p 1 -m a -n 16777216 -l 100`
 * Encrypto Group: ` ./ot.exe -r 0 -n 16777216 -o 1 &  ./ot.exe -r 1 -n 16777216 -o 1`
 * emp-toolkit:  2x 2<sup>23</sup> `./mot 0 1212 & ./mot 1 1212`

1-out-of-2 semi-honest:
 * Apricot:  `./ot.x -n 16777216 -p 0 -m a -l 100 -pas & ./ot.x -p 1 -m a -n 16777216 -l 100 -pas`
 * Encrypto Group: ` ./ot.exe -r 0 -n 16777216 -o 0 &  ./ot.exe -r 1 -n 16777216 -o 0`
 * emp-toolkit:  2*2<sup>23</sup> `./shot 0 1212 & ./shot 1 1212`

  
  
 
 ## License
 
This project has been placed in the public domain. As such, you are unrestricted in how you use it, commercial or otherwise. However, no warranty of fitness is provided. If you found this project helpful, feel free to spread the word and cite us.
 
 

## Citation
 
[IKNP03] - Yuval Ishai and Joe Kilian and Kobbi Nissim and Erez Petrank, _Extending Oblivious Transfers Efficiently_. 
 
[KOS15]  - Marcel Keller and Emmanuela Orsini and Peter Scholl, _Actively Secure OT Extension with Optimal Overhead_. [eprint/2015/546](https://eprint.iacr.org/2015/546)
 
[OOS16]  - Michele Orrù and Emmanuela Orsini and Peter Scholl, _Actively Secure 1-out-of-N OT Extension with Application to Private Set Intersection_. [eprint/2016/933](http://eprint.iacr.org/2016/933)
 
[KKRT16]  - Vladimir Kolesnikov and Ranjit Kumaresan and Mike Rosulek and Ni Trieu, _Efficient Batched Oblivious PRF with Applications to Private Set Intersection_. [eprint/2016/799](https://eprint.iacr.org/2016/799)
 
[RR16]  - Peter Rindal and Mike Rosulek, _Improved Private Set Intersection against Malicious Adversaries_. [eprint/2016/746](https://eprint.iacr.org/2016/746)

[BLNNOOSS15]  - Sai Sheshank Burra and Enrique Larraia and Jesper Buus Nielsen and Peter Sebastian Nordholt and Claudio Orlandi and Emmanuela Orsini and Peter Scholl and Nigel P. Smart, _High Performance Multi-Party Computation for Binary Circuits Based on Oblivious Transfe_. [eprint/2015/472](https://eprint.iacr.org/2015/472.pdf)

[ALSZ15]  - Gilad Asharov and Yehuda Lindell and Thomas Schneider and Michael Zohner, _More Efficient Oblivious Transfer Extensions with Security for Malicious Adversaries_. [eprint/2015/061](https://eprint.iacr.org/2015/061)
 
[NP00]  -    Moni Naor, Benny Pinkas, _Efficient Oblivious Transfer Protocols_. 

