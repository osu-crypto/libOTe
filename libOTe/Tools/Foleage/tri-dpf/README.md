# Ternary-tree DPF Implementation

A simple C implementation of Distributed Point Functions (DPFs) with several performance optimizations.

Optimizations include:

- Ternary instead of a binary tree (increases communication slightly but improves evaluation performance by having a flatter tree).
- Using batched AES for fast PRF evaluation with AES-NI.
- The half-tree optimization of [Guo et al.](https://eprint.iacr.org/2022/1431.pdf), however, this only improves performance by 2\%-4\% in the ternary-tree case.

## Dependencies

- OpenSSL
- GNU Make
- Cmake
- Clang

## Getting everything to run (tested on Ubuntu, CentOS, and MacOS)

| Install dependencies (Ubuntu):         | Install dependencies (CentOS):              |
| -------------------------------------- | ------------------------------------------- |
| `sudo apt-get install build-essential` | `sudo yum groupinstall 'Development Tools'` |
| `sudo apt-get install cmake`           | `sudo yum install cmake`                    |
| `sudo apt install libssl-dev`          | `sudo yum install openssl-devel`            |
| `sudo apt install clang`               | `sudo yum install clang`                    |

## Running tests and benchmarks

```
make
./bin/test
```

## Possible extensions (TODOs):

- Arbitrary output size and full domain evaluation optimization of [Boyle et al.](https://eprint.iacr.org/2018/707).
- Serialization for DPF keys.

## Minimal example

```c
size_t domain_size = 10;
size_t num_leaves = ipow(3, domain_size); // domain of size 3^10

size_t secret_index = 5;
uint128_t secret_msg = 1;

// common PRF keys
struct PRFKeys *prf_keys = malloc(sizeof(struct PRFKeys));
PRFKeyGen(prf_keys);

// DPF keys for each party
struct DPFKey *kA = malloc(sizeof(struct DPFKey));
struct DPFKey *kB = malloc(sizeof(struct DPFKey));

DPFGen(prf_keys, domain_size, secret_index, &secret_msg, 1, kA, kB);

uint128_t *shares0 = malloc(sizeof(uint128_t) * num_leaves);
uint128_t *shares1 = malloc(sizeof(uint128_t) * num_leaves);

// cache is used to speed up evaluations when running many
// DPF evaluations sequentially
uint128_t *cache = malloc(sizeof(uint128_t) * num_leaves);

// evaluate the DPF using the key of party A
DPFFullDomainEval(kA, cache, shares0);

// evaluate the DPF using the key of party B
DPFFullDomainEval(kB, cache, shares1);

DestroyPRFKey(prf_keys);
free(kA);
free(kB);
free(shares0);
free(shares1);
free(cache);
```

#### Performance on M1 Macbook Pro

Domain of size $3^{14} \approx 2^{22}$ and message size of 256 bits.

```
******************************************
Testing DPF.FullEval
******************************************
PASS
Avg time for DPF.FullEval: 68.29 ms
******************************************

******************************************
Testing HalfDPF.FullEval
******************************************
PASS
Avg time for HalfDPF.FullEval: 65.38 ms
******************************************
```

## Citation

```
@misc{foleage,
      author = {Maxime Bombar and Dung Bui and Geoffroy Couteau and Alain Couvreur and Clément Ducros and Sacha Servan-Schreiber},
      title = {FOLEAGE: $\mathbb{F}_4$OLE-Based Multi-Party Computation for Boolean Circuits},
      howpublished = {Cryptology ePrint Archive, Paper 2024/429},
      year = {2024},
      note = {\url{https://eprint.iacr.org/2024/429}},
      url = {https://eprint.iacr.org/2024/429}
}

```

## ⚠️ Important Warning

<b>This implementation is intended for _research purposes only_. The code has NOT been vetted by security experts.
As such, no portion of the code should be used in any real-world or production setting!</b>
