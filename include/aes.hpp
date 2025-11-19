#pragma once
#include "crypto_types.hpp"
#include <vector>

namespace crypto::aes {
    AESKey generate_key();
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const AESKey& key);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const AESKey& key);
}