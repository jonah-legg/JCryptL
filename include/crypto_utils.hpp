#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace crypto::utils {
    uint64_t random_uint64(uint64_t min, uint64_t max);
    std::vector<uint8_t> random_bytes(size_t count);
    
    uint64_t gcd(uint64_t a, uint64_t b);
    uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod);
    uint64_t mod_inverse(uint64_t a, uint64_t m);
    bool is_prime(uint64_t n);

    std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> hex_to_bytes(const std::string& hex);
}