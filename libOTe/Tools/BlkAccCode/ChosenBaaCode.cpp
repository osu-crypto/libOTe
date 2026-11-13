#include "ChosenBaaCode.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include <cstring>

namespace osuCrypto
{
    void chosenBaaCompress(MultType type, block seed, span<block> a, span<block> b)
    {
        if (type == MultType::ChosenBaa16x8)
        {
            ChosenBaaCode<8> code;
            code.config(a.size(), seed);
            if (b.empty()) code.dualEncode(a);
            else code.dualEncode2(a, b);
        }
        else if (type == MultType::ChosenBaa16x4)
        {
            ChosenBaaCode<4> code;
            code.config(a.size(), seed);
            if (b.empty()) code.dualEncode(a);
            else code.dualEncode2(a, b);
        }
        else throw std::invalid_argument("Not a chosen BAA profile.");
    }

    namespace
    {
        using Seed = std::array<u8, 16>;
        using Commitment = std::array<u8, 32>;

        OC_NOINLINE Commitment commitSeed(const Seed& seed)
        {
            RandomOracle hash(32);
            constexpr char domain[] = "libOTe/chosen-baa/seed/v1";
            hash.Update(domain, sizeof(domain));
            hash.Update(seed.data(), seed.size());
            Commitment result;
            hash.Final(result.data());
            return result;
        }

        OC_NOINLINE void combineSeeds(const Seed& a, const Seed& b, block& output)
        {
            Seed result;
            for (u64 i = 0; i < result.size(); ++i)
                result[i] = a[i] ^ b[i];
            std::memcpy(&output, result.data(), result.size());
        }
    }

    task<> chosenBaaSeed(bool sender, PRNG& prng, Socket& chl, block& seed)
    {
        // Byte arrays require no SIMD alignment in a coroutine frame. Each
        // send is awaited before its storage is reused or destroyed.
        Seed mine{}, theirs{};
        Commitment commitment{};
        prng.get(mine.data(), mine.size());
        if (sender)
        {
            commitment = commitSeed(mine);
            co_await chl.send(commitment);
            co_await chl.recv(theirs);
            co_await chl.send(mine);
        }
        else
        {
            co_await chl.recv(commitment);
            co_await chl.send(mine);
            co_await chl.recv(theirs);
            if (commitSeed(theirs) != commitment)
                throw std::runtime_error("Chosen BAA seed commitment mismatch.");
        }
        combineSeeds(mine, theirs, seed);
    }
}
