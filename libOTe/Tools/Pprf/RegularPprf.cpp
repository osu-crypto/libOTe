#include "cryptoTools/Crypto/AES.h"

namespace osuCrypto {
    // A public PRF/PRG that we will use for deriving the GGM tree.
    extern const std::array<AES, 2> gGgmAes = []() {
        std::array<AES, 2> aes;
        aes[0].setKey(toBlock(3242342));
        aes[1].setKey(toBlock(8993849));
        return aes;
    }();
}
