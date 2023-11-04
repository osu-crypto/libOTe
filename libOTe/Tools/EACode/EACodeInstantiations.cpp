
#define EACODE_INSTANTIONATIONS
#include "EACode.cpp"

namespace osuCrypto
{
    template void EACode::dualEncode<block>(span<block> e, span<block> w);
    template void EACode::dualEncode<u8>(span<u8> e, span<u8> w);
    template void EACode::accumulate<block>(span<block> e);
    template void EACode::accumulate<u8>(span<u8> e);

    template void EACode::dualEncode2<block, u8>(span<block> e, span<block> w, span<u8> e2, span<u8> w2);
    template void EACode::dualEncode2<block, block>(span<block> e, span<block> w, span<block> e2, span<block> w2);
    template void EACode::accumulate<block,u8>(span<block>e0, span<u8> e);
}