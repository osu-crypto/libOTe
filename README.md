# libOTe
A fast and portable C++11 library for Oblivious Transfer extension (OTe). The primary design goal of this libary to obtain *high performance* while being *easy to use*.  This library currently implements:

* The semi-honest 1-out-of-2 OT [IKNP03] protocol.
* The semi-honest 1-out-of-N [[KKRT16]](https://eprint.iacr.org/2016/799) protocol. 
* The malicious secure 1-out-of-2 [[KOS15]](https://eprint.iacr.org/2015/546) protocol.
* The malicious secure 1-out-of-N [[OOS16]](http://eprint.iacr.org/2016/933) protocol.
* The malicious secure approximate K-out-of-N [[RR16]](https://eprint.iacr.org/2016/746) protocol.
* The malicious secure 1-out-of-2 base OT  [NP00] protocol.

## Introduction

This library provides several different classes of OT protocols. First is the base OT protocol of Naor Prinkas [NP00]. This protocol bootstraps all the other OT extension protocols.  Within the OT extension protocols, we have 1-out-of-2, 1-out-of-N and ~K-out-of-N, both in the semi-honest and malicious settings.

All implementations are highly optimized using fast SSE instructions and vectorization to obtains optimal performance both in the single and multi-threaded setting. See the **Performance** section for a comparison between protocols and to other libraries. 



#### Lisence

This project has been placed in the public domain. As such, you are unrestricted in how you use it, commercial or otherwise. However, no warranty of fitness is provided. If you found this project helpful, feel free to spread the word and cite us.



## Install

The library is *cross platform* and has been tested on both Windows and Linux. The library should work on MAC but it has not been tested. There are two library dependancies including [Boost](http://www.boost.org/), and [Miracl](https://www.miracl.com/index) . For each, we provide a script that automates the download and build steps. The version of Miracl used by this library requires specific configuration and therefore we advice using the coned repository that we provide.

### Windows

This project was developed using visual studio and contains the associated solution and project files. Before building the solution, the third party libraries [Boost](http://www.boost.org/), and [Miracl](https://www.miracl.com/index) must be obtained. We provide powershell scripts that automate this processes located in the `./thirdparty/win/` directory. Make sure that you have set the execution policy to unrestricted, i.e. run `Set-ExecutionPolicy  Unrestricted` as admin.

By default, these scripts will download the libraries to this folder. However, the visual studio projects will also look form them at `C:\\libs\`.

Once the scripts have finished, visual studio should be able to build the project. The Test Explorer should be able to find all the unit tests and hopefully they all pass. Unit tests can also be run from the command line with the arguments

`frontend.exe -u`

For the full set of command line options, simply execute the frendend with no arguments.




### Linux

Once cloned, the libraries listed above must be built. In `./thirdparty/linux` there are scripts that will download and build all of the libraries that are listed above. To build the libOTe and the associated frontend:

`./make `

To see all the command line options, execute the program 

`./Release/frontend.exe`


## Performance

The running time in seconds for computing n=2<sup>24</sup> OTs on an Intel Xeon server. 


| *Type*                	| *Security*  	| *Protocol*     	| libOTe 	| [Encrypto Group](https://github.com/encryptogroup/OTExtension) 	| [Apricot](https://github.com/bristolcrypto/apricot)	| OOS16	| [Crypto BIU](https://github.com/cryptobiu) 	|
|---------------------	|-----------	|--------------	|----------------	|----------------	|---------	|---------	|------------	|
| 1-out-of-N (N=2<sup>76</sup>) 	| malicious 	| OOS16    	    | **11.7**       	| ~              	| ~     	| 24**     	| ~          	|
| 1-out-of-N (N=2<sup>128</sup>)   | passive   	| KKRT16      	| **9.2**        	| ~              	| ~       	| ~       	| ~          	|
| 1-out-of-2          	| malicious 	| ALSZ15        	| ~          	    | 93.9*          	| ~       	| ~       	| ~          	|
| 1-out-of-2           	| malicious   	| KOS15       	| **4.8**        	| ~              	| 7.1     	| ~        	| TODO       	|
| 1-out-of-2          	| passive   	| IKNP03       	| **4.7**        	| 93.9           	| 6.8     	| ~     	| TODO       	|

as of 11/6/2016.

\* Estmated from running the Encrypto Group implementation for n=2<sup>20</sup>.  Program would crash for n=2<sup>24</sup>.

\** This timing was taken from the [[OOS16]](http://eprint.iacr.org/2016/933) paper and their implementation used multiple threads. The number was not specified. When using the libOTe implementaion with multiple threads, a timing of 2.6 seconds was obtained.

It should be noted that the libOTe implementation uses the Boost ASIO library to perform  more efficient asynchonis network IO. This involves using a background thread to help process network data. As such, this is not a completely fair comparison but we don't expect it to have a large impact.

#### Protocol Details
The 1-out-of-N [OOS16] protocol currently is set to work forn N=2<sup>76</sup> but is capable of supporting arbitrary codes given the generator matrix in text format. See `./libOTe/OT/Tools/Bch511.txt` for an example.

The 1-out-of-N  [KKRT16] for arbitrary N is also implemented and slightly faster than [OOS16]. However, [KKRT16] is in the semi-honest setting.

The approximate K-out-of-N OT [RR16] protocol is also implemented. This protocol allows for a rough bound on the value K with a very light weight cut and choose technique. It was introducted for a PSI protocol that builds on a Garbled Bloom Filter.

## Help

Contact Peter Rindal rindalp@oregonstate.edu for any assistance on building or running the library.



## Citation

[IKNP03] - Yuval Ishai and Joe Kilian and Kobbi Nissim and Erez Petrank, _Extending Oblivious Transfers Efficiently_. 

[KOS15]  - Marcel Keller and Emmanuela Orsini and Peter Scholl, _Actively Secure OT Extension with Optimal Overhead_. [eprint/2015/546](https://eprint.iacr.org/2015/546)

[OOS16]  - Michele Orrù and Emmanuela Orsini and Peter Scholl, _Actively Secure 1-out-of-N OT Extension with Application to Private Set Intersection_. [eprint/2016/933](http://eprint.iacr.org/2016/933)

[KKRT16]  - Vladimir Kolesnikov and Ranjit Kumaresan and Mike Rosulek and Ni Trieu, _Efficient Batched Oblivious PRF with Applications to Private Set Intersection_. [eprint/2016/799](https://eprint.iacr.org/2016/799)

[RR16]  - Peter Rindal and Mike Rosulek, _Improved Private Set Intersection against Malicious Adversaries_. [eprint/2016/746](https://eprint.iacr.org/2016/746)


[NP00]  -    Moni Naor, Benny Pinkas, _Efficient Oblivious Transfer Protocols_. 