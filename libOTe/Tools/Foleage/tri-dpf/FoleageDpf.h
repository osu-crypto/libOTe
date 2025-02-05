#pragma once

#include <stdio.h>
#include <string.h>

#include "libOTe/Tools/Foleage/FoleageUtils.h"
#include "libOTe/Tools/Foleage/tri-dpf/FoleagePrf.h"


namespace osuCrypto
{
    struct DPFKey
    {
        PRFKeys* prf_keys;
        AlignedUnVector<unsigned char> k;
        size_t msg_len;
        size_t size;
    };

    void DPFGen(
        PRFKeys& prf_keys,
        size_t domain_size,
        size_t index,
        span<uint128_t> msg_blocks,
        size_t msg_block_len,
        DPFKey& k0,
        DPFKey& k1, 
        PRNG& prng);

    void DPFFullDomainEval(
        DPFKey& k,
        span<uint128_t> cache,
        span<uint128_t> output);

}
