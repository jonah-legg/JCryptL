#pragma once
#include "crypto_types.hpp"

namespace crypto {
    class KeyGenerator {
    public:
        static RSAKeyPair generate_rsa();
    };
}