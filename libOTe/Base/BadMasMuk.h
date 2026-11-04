#pragma once
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#ifdef ENABLE_BMM

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>

namespace osuCrypto
{
    // The tightly secure UC base OT of Badrinarayanan, Masny and Mukherjee,
    // "Efficient and Tight Oblivious Transfer from PKE with Tight Multi-User
    // Security" (ePrint 2022/415, Fig. 2), instantiated with hashed ElGamal
    // over Edwards25519.
    //
    // Receiver with choice b sends (r, c0, c1) where
    //     pk_b    = x * G,   chat_b, c_b <- {0,1}^lambda
    //     r       = pk_b - Hhat(b, chat_b)
    //     c_{1-b} = chat_b ^ H(b, r, c_b).
    // The sender recomputes, for i in {0,1},
    //     chat_i  = c_{1-i} ^ H(i, r, c_i)
    //     pk_i    = r + Hhat(i, chat_i)
    // and, as in MasnyRindal, encrypts by publishing one key A = a * G for
    // the whole batch and deriving m_i = KDF(otIndex, i, 8a * pk_i).
    //
    // Each OT costs the receiver one fixed-base and one fixed-point scalar
    // multiplication plus one hash-to-curve, and the sender two hash-to-curve
    // and two variable-base multiplications. Communication is 32 + 2*16 = 64
    // bytes per OT from the receiver (same as MasnyRindal) plus 32 bytes total
    // from the sender, and both messages can be sent in parallel.
    //
    // Security notes (deviations from the paper's theorem; our own analysis,
    // not peer reviewed):
    //
    // * Reused sender key. The paper's tight proof (Theorem 1, ElGamal under
    //   DDH via Lemma 1) assumes fresh encryption randomness per ciphertext.
    //   We reuse one A across the batch, the batching that [MRR21] (ePrint
    //   2021/682) shows is safe for MR-style protocols once the KDF
    //   includes the OT index. Fresh randomness would cost about 29% more
    //   time and 64 more bytes per OT.
    //
    // * Intended model: AGM + ROM, tight to DL. The simulator extracts the
    //   choice bit from the algebraic representation of r rather than by
    //   programming Hhat, so the malicious-receiver case has no statistical
    //   term depending on lambda. The only lambda-dependent term is about
    //   n*q/2^lambda from programming Hhat in the corrupt-sender
    //   simulation, which 128-bit tags keep near 2^-40 for q = 2^80 and
    //   batches of up to about 256 OTs.
    //
    // * Plain ROM (no AGM). Here the bound is tight under Gap-DH, but as we
    //   read the proof of Lemma 5 (hybrid S1), its q^2/2^lambda statistical
    //   term omits abort events of order q^3/2^lambda and q^4/2^lambda.
    //   With 128-bit tags that bound is only meaningful up to about 2^32
    //   random-oracle queries. This is a gap in the proof, not a known
    //   attack; the authors have confirmed it (Nov 2026).
    //
    // tagSize in the .cpp is the only knob for lambda; bump the domain-string
    // version if it changes.
    class BadMasMuk : public OtReceiver, public OtSender
    {
    public:

        task<> receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Socket& chl,
            u64 numThreads)
        {
            return receive(choices, messages, prng, chl);
        }

        task<> send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl,
            u64 numThreads)
        {
            return send(messages, prng, chl);
        }

        task<> receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Socket& chl) override;

        task<> send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl) override;
    };

}
#endif
