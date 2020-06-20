![](./titleOSU.PNG)
=====

[![Build Status](https://travis-ci.org/osu-crypto/libOTe.svg?branch=master)](https://travis-ci.org/osu-crypto/libOTe)

A fast and portable C++11 library for Oblivious Transfer extension (OTe). The 
primary design goal of this library to obtain *high performance* while being 
*easy to use*.  This library currently implements:
 
* The semi-honest 1-out-of-2 OT [IKNP03].
* The semi-honest 1-out-of-2 Silent OT [[BCGIKRS19]](https://eprint.iacr.org/2019/1159.pdf).
* The semi-honest 1-out-of-2 Delta-OT [IKNP03],[[BLNNOOSS15]](https://eprint.iacr.org/2015/472.pdf).
* The semi-honest 1-out-of-N OT [[KKRT16]](https://eprint.iacr.org/2016/799). 
* The malicious secure 1-out-of-2 OT [[KOS15]](https://eprint.iacr.org/2015/546).
* The malicious secure 1-out-of-2 Delta-OT [[KOS15]](https://eprint.iacr.org/2015/546),[[BLNNOOSS15]](https://eprint.iacr.org/2015/472.pdf).
* The malicious secure 1-out-of-N OT [[OOS16]](http://eprint.iacr.org/2016/933).
* The malicious secure approximate K-out-of-N OT [[RR16]](https://eprint.iacr.org/2016/746).
* The malicious secure 1-out-of-2 base OT [NP01].
* The malicious secure 1-out-of-2 base OT [[CO15]](https://eprint.iacr.org/2015/267.pdf) (Faster Linux ASM version disabled by default).
* The malicious secure 1-out-of-2 base OT [[MR19]](https://eprint.iacr.org/2019/706.pdf) 
 
## Introduction
 
This library provides several different classes of OT protocols. First is the 
base OT protocol of Naor Pinkas [NP01]. This protocol bootstraps all the other
OT extension protocols.  Within the OT extension protocols, we have 1-out-of-2,
1-out-of-N and K-out-of-N, both in the semi-honest and malicious settings.

All implementations are highly optimized using fast SSE instructions and vectorization
to obtain optimal performance both in the single and multi-threaded setting. See 
the **Performance** section for a comparison between protocols and to other libraries. 
 
Networking can be performed using both the sockets provided by the library and 
external socket classes. See the [networking tutorial](https://github.com/ladnir/cryptoTools/blob/57220fc45252d089a7fd90816144e447a2ce02b8/frontend_cryptoTools/Tutorials/Network.cpp#L264)
for an example.

## Example Code
A minimal working example showing how to perform `n` OTs using the IKNP protocol.
```cpp
void minimal()
{
    // Setup networking. See cryptoTools\frontend_cryptoTools\Tutorials\Network.cpp
    IOService ios;
    Channel senderChl = Session(ios, "localhost:1212", SessionMode::Server).addChannel();
    Channel recverChl = Session(ios, "localhost:1212", SessionMode::Client).addChannel();

    // The number of OTs.
    int n = 100;

    // The code to be run by the OT receiver.
    auto recverThread = std::thread([&]() {
        PRNG prng(sysRandomSeed());
        IknpOtExtReceiver recver;

        // Choose which messages should be received.
        BitVector choices(n);
        choices[0] = 1;
        //...

        // Receive the messages
        std::vector<block> messages(n);
        recver.receiveChosen(choices, messages, prng, recverChl);

        // messages[i] = sendMessages[i][choices[i]];
    });

    PRNG prng(sysRandomSeed());
    IknpOtExtSender sender;

    // Choose which messages should be sent.
    std::vector<std::array<block, 2>> sendMessages(n);
    sendMessages[0] = { toBlock(54), toBlock(33) };
    //...

    // Send the messages.
    sender.sendChosen(sendMessages, prng, senderChl);
    recverThread.join();
}
```

## Performance
 
The running time in seconds for computing n=2<sup>24</sup> OTs on a single Intel 
Xeon server (`2 36-cores Intel Xeon CPU E5-2699 v3 @ 2.30GHz and 256GB of RAM`)
as of 11/16/2016. All timings shown reflect a "single" thread per party, with the 
expection that network IO in libOTe is performed in the background by a separate thread. 
 
 
| *Type*                	| *Security*  	| *Protocol*     	| libOTe (SHA1/AES)	| [Encrypto Group](https://github.com/encryptogroup/OTExtension) (SHA256) 	| [Apricot](https://github.com/bristolcrypto/apricot) (AES-hash)	| OOS16 (blake2)	| [emp-toolkit](https://github.com/emp-toolkit) (AES-hash)	|
|---------------------	|-----------	|--------------	|----------------	|----------------	|---------	|---------	|------------	|
| 1-out-of-N (N=2<sup>76</sup>) | malicious | OOS16    	| **10.6 / 9.2**       	| ~              	| ~     	| 24**     	| ~          	|
| 1-out-of-N (N=2<sup>128</sup>)| passive| KKRT16      	| **9.2 / 6.7**        	| ~              	| ~       	| ~       	| ~          	|
| 1-out-of-2 Delta-OT  	| malicious   	| KOS15       	| **1.9***        		| ~              	| ~     	| ~        	|  ~      	|
| 1-out-of-2 Delta-OT  	| passive   	| KOS15       	| **1.7***        		| ~              	| ~     	| ~        	|  ~      	|
| 1-out-of-2          	| malicious 	| ALSZ15        | ~          	        | 17.3          	| ~       	| ~       	|  10         	|
| 1-out-of-2           	| malicious   	| KOS15       	| **3.9 / 0.7**        	| ~              	| 1.1     	| ~        	|  2.9       	|
| 1-out-of-2          	| passive   	| IKNP03       	| **3.7 / 0.6**        	| 11.3          	| **0.6**   | ~     	|  2.7      	|
| 1-out-of-2 Base      	| malicious   	| CO15       	| **1,592/~**        	| ~              	|~       	| ~        	| ~          	|
| 1-out-of-2 Base     	| malicious   	| NP00       	| **12,876/~**        	| ~             	| ~		    | ~     	| ~         	|
 

 
## Install
 
The library is *cross platform* and has been tested on Windows, Mac and Linux. 
There is one mandatory dependency on [Boost 1.69](http://www.boost.org/) (networking),
and three **optional dependencies** on, [Miracl](https://www.miracl.com/),
[Relic](https://github.com/ladnir/relic/) or
[SimplestOT](https://github.com/osu-crypto/libOTe/tree/master/SimplestOT) (Unix only)
for Base OTs. Any or all of these dependenies can be enabled. See below. 

 
### Windows

In `Powershell`, this will set up the project

```
git clone --recursive https://github.com/osu-crypto/libOTe.git
cd libOTe/cryptoTools/thirdparty/win
getBoost.ps1 
cd ../../..
libOTe.sln
```

To see all the command line options, execute the program 

`frontend.exe` 

**Boost and visual studio 2017:**  If boost does not build with visual studio 2017 
follow [these instructions](https://stackoverflow.com/questions/41464356/build-boost-with-msvc-14-1-vs2017-rc). 

**Enabling [Relic](https://github.com/relic-toolkit/relic) (for fast base OTs):**
 * Build the library:
```
git clone https://github.com/ladnir/relic.git
cd relic
cmake . -DMULTI=OPENMP -DCMAKE_INSTALL_PREFIX:PATH=C:\libs  -DCMAKE_GENERATOR_PLATFORM=x64 -DRUNTIME=MT
cmake --build .
cmake --install .
```
 * Edit the config file [libOTe/cryptoTools/cryptoTools/Common/config.h](https://github.com/ladnir/cryptoTools/blob/master/cryptoTools/Common/config.h) to include `#define ENABLE_RELIC`.

**Enabling Miracl (for base OTs):**
 * `cd libOTe/cryptoTools/thirdparty/win`
 * `getMiracl.ps1 ` (If the Miracl script fails to find visual studio 2017,  manually open and build the Miracl solution.)
 * `cd ../../..`
 * Edit the config file [libOTe/cryptoTools/cryptoTools/Common/config.h](https://github.com/ladnir/cryptoTools/blob/master/cryptoTools/Common/config.h) to include `#define ENABLE_MIRACL`.

**IMPORTANT:** By default, the build system needs the NASM compiler to be located
at `C:\NASM\nasm.exe`. In the event that it isn't, there are two options, install it, 
or enable the pure c++ implementation:
 * Remove  `cryptoTools/Crypto/asm/sha_win64.asm` from the cryptoTools Project.
 * Edit the config file [libOTe/cryptoTools/cryptoTools/Common/config.h](https://github.com/ladnir/cryptoTools/blob/master/cryptoTools/Common/config.h) to remove `#define ENABLE_NASM`.



### Linux / Mac
 
 In short, this will build the project (without base OTs)

```
git clone --recursive https://github.com/osu-crypto/libOTe.git
cd libOTe/cryptoTools/thirdparty/linux
bash boost.get
cd ../../..
cmake .
make
```

This will build the minimum version of the library (wihtout base OTs). The libraries 
will be placed in `libOTe/lib` and the binary `frontend_libOTe` will be placed in 
`libOTe/bin` To see all the command line options, execute the program 
 
`./bin/frontend_libOTe`


**Enable Base OTs using:**
 * `cmake .  -DENABLE_MIRACL=ON`: Build the library with integration to the
     [Miracl](https://github.com/miracl/MIRACL) library. Requires building miracl 
 `   cd libOTe/cryptoTools/thirdparty/linux; bash miracl.get`.

 * `cmake .  -DENABLE_RELIC=ON`: Build the library with integration to the 
      [Relic](https://github.com/ladnir/relic/) library. Requires that
      relic is built with `cmake . -DMULTI=OPENMP` and installed. **Requires an older version of relic found here [Relic](https://github.com/ladnir/relic/)**
 * **Linux Only**: `cmake .  -DENABLE_SIMPLESTOT=ON`: Build the library with integration to the 
      [SimplestOT](https://github.com/osu-crypto/libOTe/tree/master/SimplestOT) 
       library implementing a base OT. Also works with only relic but is slower.

**Other Options:**
 * `cmake .  -DENABLE_CIRCUITS=ON`: Build the library with the circuit library enabled.
 * `cmake .  -DENABLE_NASM=ON`: Build the library with the assembly base SHA1 implementation. Requires the NASM compiler.
 


**Note:** In the case that miracl or boost is already installed, the steps 
`cd libOTe/cryptoTools/thirdparty/linux; bash boost.get` can be skipped and CMake will attempt 
to find them instead. Boost is found with the CMake findBoost package and miracl
is found with the `find_library(miracl)` command.
 


### Linking

 You can either `make install` on linux or link libOTe's source tree. In the latter 
 case, you will need to include the following:

1) .../libOTe
2) .../libOTe/cryptoTools
3) .../libOTe/cryptoTools/thirdparty/linux/boost
4) .../libOTe/cryptoTools/thirdparty/linux/miracl/miracl <i>(if enabled)</i>
5) [Relic includes] <i>(if enabled)</i>

and link:
1) .../libOTe/bin/liblibOTe.a
2) .../libOTe/bin/libcryptoTools.a
3) .../libOTe/bin/libSimplestOT.a    <i>(if enabled)</i>
3) .../libOTe/bin/libKyberOT.a       <i>(if enabled)</i>
4) .../libOTe/cryptoTools/thirdparty/linux/boost/stage/lib/libboost_system.a
5) .../libOTe/cryptoTools/thirdparty/linux/boost/stage/lib/libboost_thread.a
6) .../libOTe/cryptoTools/thirdparty/linux/miracl/miracl/source/libmiracl.a <i>(if enabled)</i>
7) [Relic binary] <i>(if enabled)</i>

**Note:** On windows the linking paths follow a similar pattern.

## Help
 
Contact Peter Rindal peterrindal@gmail.com for any assistance on building 
or running the library.

## Citing

 Spread the word!

```
@misc{libOTe,
    author = {Peter Rindal},
    title = {{libOTe: an efficient, portable, and easy to use Oblivious Transfer Library}},
    howpublished = {\url{https://github.com/osu-crypto/libOTe}},
}
```
 
 ## License
 
This project has been placed in the public domain. As such, you are unrestricted in how 
you use it, commercial or otherwise. However, no warranty of fitness is provided. If you 
found this project helpful, feel free to spread the word and cite us.
 
 

## Citation
 
[IKNP03] - Yuval Ishai and Joe Kilian and Kobbi Nissim and Erez Petrank, _Extending Oblivious Transfers Efficiently_. 
 
[KOS15]  - Marcel Keller and Emmanuela Orsini and Peter Scholl, _Actively Secure OT Extension with Optimal Overhead_. [eprint/2015/546](https://eprint.iacr.org/2015/546)
 
[OOS16]  - Michele Orrù and Emmanuela Orsini and Peter Scholl, _Actively Secure 1-out-of-N OT Extension with Application to Private Set Intersection_. [eprint/2016/933](http://eprint.iacr.org/2016/933)
 
[KKRT16]  - Vladimir Kolesnikov and Ranjit Kumaresan and Mike Rosulek and Ni Trieu, _Efficient Batched Oblivious PRF with Applications to Private Set Intersection_. [eprint/2016/799](https://eprint.iacr.org/2016/799)
 
[RR16]  - Peter Rindal and Mike Rosulek, _Improved Private Set Intersection against Malicious Adversaries_. [eprint/2016/746](https://eprint.iacr.org/2016/746)

[BLNNOOSS15]  - Sai Sheshank Burra and Enrique Larraia and Jesper Buus Nielsen and Peter Sebastian Nordholt and Claudio Orlandi and Emmanuela Orsini and Peter Scholl and Nigel P. Smart, _High Performance Multi-Party Computation for Binary Circuits Based on Oblivious Transfer_. [eprint/2015/472](https://eprint.iacr.org/2015/472.pdf)

[ALSZ15]  - Gilad Asharov and Yehuda Lindell and Thomas Schneider and Michael Zohner, _More Efficient Oblivious Transfer Extensions with Security for Malicious Adversaries_. [eprint/2015/061](https://eprint.iacr.org/2015/061)
 
[NP01]  -    Moni Naor, Benny Pinkas, _Efficient Oblivious Transfer Protocols_. 

