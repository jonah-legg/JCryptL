#pragma once
#include "crypto_types.hpp"
#include <vector>

namespace crypto::rsa {
    RSAKeyPair generate_keypair();
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const RSAPublicKey& key);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const RSAPrivateKey& key);
}