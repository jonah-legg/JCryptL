#include "crypto_types.hpp"
#include "crypto_utils.hpp"
#include <vector>
#include <stdexcept>
#include <algorithm>

namespace crypto::rsa {
    namespace {
        constexpr size_t KEY_SIZE = 64;
        constexpr uint64_t PUBLIC_EXPONENT = 65537;
        constexpr size_t BLOCK_SIZE = sizeof(uint64_t) - 1;
    }

    RSAKeyPair generate_keypair() {
        uint64_t p = 0, q = 0, n = 0, phi = 0;

        while (true) {
            do {
                p = utils::random_uint64(1ULL << 16, 1ULL << 31);
            } while (!utils::is_prime(p));
            
            do {
                q = utils::random_uint64(1ULL << 16, 1ULL << 31);
            } while (!utils::is_prime(q) || p == q);

            n = p * q;
            if (n < p || n < q) continue;

            phi = (p - 1) * (q - 1);
            if (phi < p-1 || phi < q-1) continue;

            if (utils::gcd(PUBLIC_EXPONENT, phi) == 1) {
                break;
            }
        }

        uint64_t d = utils::mod_inverse(PUBLIC_EXPONENT, phi);
        
        return RSAKeyPair{
            RSAPublicKey{n, PUBLIC_EXPONENT},
            RSAPrivateKey{n, d}
        };
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const RSAPublicKey& key) {
        std::vector<uint8_t> encrypted;
        
        for (size_t i = 0; i < data.size(); i += BLOCK_SIZE) {
            uint64_t block = 0;
            size_t bytes_in_block = std::min(BLOCK_SIZE, data.size() - i);
            
            for (size_t j = 0; j < bytes_in_block; j++) {
                block |= static_cast<uint64_t>(data[i + j]) << (j * 8);
            }

            uint64_t encrypted_block = utils::mod_pow(block, key.e, key.n);

            for (size_t j = 0; j < sizeof(uint64_t); j++) {
                encrypted.push_back(static_cast<uint8_t>((encrypted_block >> (j * 8)) & 0xFF));
            }
        }

        return encrypted;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const RSAPrivateKey& key) {
        std::vector<uint8_t> decrypted;
        
        for (size_t i = 0; i < data.size(); i += sizeof(uint64_t)) {
            uint64_t encrypted_block = 0;
            for (size_t j = 0; j < sizeof(uint64_t) && i + j < data.size(); j++) {
                encrypted_block |= static_cast<uint64_t>(data[i + j]) << (j * 8);
            }

            uint64_t decrypted_block = utils::mod_pow(encrypted_block, key.d, key.n);
            for (size_t j = 0; j < BLOCK_SIZE && decrypted.size() < data.size(); j++) {
                decrypted.push_back(static_cast<uint8_t>((decrypted_block >> (j * 8)) & 0xFF));
            }
        }

        return decrypted;
    }
}