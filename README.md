![](./titleOSU.PNG)
=====

<!-- [![Build Status](https://travis-ci.org/osu-crypto/libOTe.svg?branch=master)](https://travis-ci.org/osu-crypto/libOTe) -->

A fast and portable C++17 library for Oblivious Transfer extension (OTe). The 
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
base OT protocol of [NP01, CO15, MR19]. These protocol bootstraps all the other
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
 

 
## Build
 
The library is *cross platform* and has been tested on Windows, Mac and Linux. 
There is one mandatory dependency on [Boost 1.75](http://www.boost.org/) (networking),
and two **optional dependencies** on [libsodium](https://doc.libsodium.org/) or
[SimplestOT](https://github.com/osu-crypto/libOTe/tree/master/SimplestOT) (Unix only)
for Base OTs.
The Moeller POPF Base OTs additionally require the `noclamp` option for Montgomery curves, which is currently only in a [fork](https://github.com/osu-crypto/libsodium) of libsodium.
CMake and Python 3 are also required to build and visual studio 2019 is assumed on windows.
 

```
git clone --recursive https://github.com/osu-crypto/libOTe.git
cd libOTe
python build.py setup boost
python build.py -DENABLE_SODIUM=ON -DENABLE_ALL_OT=ON
```
It is possible to build only the protocol(s) that are desired via cmake command. In addition, if boost is already installed, then `boost` can be ommitted from `python build.py setup boost`.

See the output of `python build.py` or `cmake .` for available compile options. For example, 
```
python build.py -DENABLE_IKNP=ON
```
will only build the [iknp04] protocol.

The main executable with examples is `frontend` and is located in the build directory, eg `out/build/linux/frontend/frontend.exe, out/build/x64-Release/frontend/Release/frontend.exe` depending on the OS. 

**Enabling/Disabling [libsodium](https://doc.libsodium.org/) (for base OTs):**
 * libsodium can be disabled by using the build commands
```
python build.py setup boost
python build.py -DENABLE_IKNP=ON
```
This will disable many/all of the supported base OT protocols. In addition, you will need to manually enable the specific protocols you desire, eg as above.
In the other direction, when enabling libsodium, if libsodium is installed in a prefix rather than globally tell cmake where to look for it with
```
PKG_CONFIG_PATH=/path/to/folder_containing_libsodium.pc cmake . -DENABLE_SODIUM=ON
```

Installing libOTe is only partially supported. 

### Linking

The helper scripts `cmake/loadCacheCar.cmake, cmake/libOTeHeler.cmake` can be used to find all dependencies when *not* installing libOTe. See [libPSI](https://github.com/osu-crypto/libPSI/blob/8f6d99106b18126b19b55c4fdc43402209a50d02/CMakeLists.txt#L123) for an example. In addition, the libOTe build script/cmake will output many of the dependency while the remaining will be located in the build directory.

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

