
#include "TungstenData.h"

namespace osuCrypto
{

    constexpr std::array<std::array<u8, 4>, 10> TableTungsten10x4::data;
    constexpr std::array<std::array<u8, 4>, 8> TableTungsten8x4::data;
    constexpr std::array<std::array<u16, 4>, 1024> TableTungsten1024x4::data;
    constexpr std::array<std::array<u16, 7>, 1024> TableTungsten1024x7::data;

    constexpr std::array<std::array<u8, 4>, 128> TableTungsten128x4::data;
}