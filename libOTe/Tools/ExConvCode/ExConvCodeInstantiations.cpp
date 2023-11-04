
#define EXCONVCODE_INSTANTIATIONS
#include "ExConvCode.cpp"

namespace osuCrypto
{

    template void ExConvCode::dualEncode<block>(span<block> e);
    template void ExConvCode::dualEncode<u8>(span<u8> e);
    template void ExConvCode::dualEncode<block>(span<block> e, span<block> w);
    template void ExConvCode::dualEncode<u8>(span<u8> e, span<u8> w);
    template void ExConvCode::dualEncode2<block, u8>(span<block>, span<u8> e);
    template void ExConvCode::dualEncode2<block, block>(span<block>, span<block> e);

    template void ExConvCode::accumulate<block, u8>(span<block>, span<u8> e);
    template void ExConvCode::accumulate<block, block>(span<block>, span<block> e);
}
