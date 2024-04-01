
#define EXCONVCODE_INSTANTIATIONS
#include "ExConvCodeOld.cpp"
#ifdef LIBOTE_ENABLE_OLD_EXCONV

namespace osuCrypto
{

    template void ExConvCodeOld::dualEncode<block>(span<block> e);
    template void ExConvCodeOld::dualEncode<u8>(span<u8> e);
    template void ExConvCodeOld::dualEncode<block>(span<block> e, span<block> w);
    template void ExConvCodeOld::dualEncode<u8>(span<u8> e, span<u8> w);
    template void ExConvCodeOld::dualEncode2<block, u8>(span<block>, span<u8> e);
    template void ExConvCodeOld::dualEncode2<block, block>(span<block>, span<block> e);

    template void ExConvCodeOld::accumulate<block, u8>(span<block>, span<u8> e);
    template void ExConvCodeOld::accumulate<block, block>(span<block>, span<block> e);
}

#endif