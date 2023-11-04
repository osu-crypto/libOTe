#define EXPANDER_INSTANTATIONS
#include "Expander.cpp"

namespace osuCrypto
{

    template void ExpanderCode::expand<block, true>(span<const block> e, span<block> w) const;
    template void ExpanderCode::expand<block, false>(span<const block> e, span<block> w) const;
    template void ExpanderCode::expand<u8, true>(span<const u8> e, span<u8> w) const;
    template void ExpanderCode::expand<u8, false>(span<const u8> e, span<u8> w) const;

    template void ExpanderCode::expand<block, u8, true>(
        span<const block> e, span<const u8> e2,
        span<block> w, span<u8> w2) const;
    template void ExpanderCode::expand<block, u8, false>(
        span<const block> e, span<const u8> e2,
        span<block> w, span<u8> w2) const;


    template void ExpanderCode::expand<block, block, true>(
        span<const block> e, span<const block> e2,
        span<block> w, span<block> w2) const;
    //template void ExpanderCode::expand<block, block, false>(
    //    span<const block> e, span<const block> e2,
    //    span<block> w, span<block> w2) const;
}