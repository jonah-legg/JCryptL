#pragma once
#include <cstdint>
#include <vector>

namespace crypto {
    using AESKey = std::array<uint8_t, 16>;

    struct RSAPublicKey {
        uint64_t n;
        uint64_t e;
    };

    struct RSAPrivateKey {
        uint64_t n;
        uint64_t d;
    };

    struct RSAKeyPair {
        RSAPublicKey pub;
        RSAPrivateKey priv;
    };
}