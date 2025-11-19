#pragma once
#include <cstdint>
#include <array>
#include <vector>

namespace crypto {
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