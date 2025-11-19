#include "crypto_utils.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <chrono>

namespace crypto::utils {

namespace {
    // Thread-safe random number generator
    std::mt19937_64& get_random_engine() {
        static thread_local std::mt19937_64 engine(
            std::chrono::high_resolution_clock::now().time_since_epoch().count()
        );
        return engine;
    }
}

uint64_t random_uint64(uint64_t min, uint64_t max) {
    std::uniform_int_distribution<uint64_t> dist(min, max);
    return dist(get_random_engine());
}

std::vector<uint8_t> random_bytes(size_t count) {
    std::vector<uint8_t> bytes(count);
    std::uniform_int_distribution<int> dist(0, 255);
    
    for (size_t i = 0; i < count; ++i) {
        bytes[i] = static_cast<uint8_t>(dist(get_random_engine()));
    }
    
    return bytes;
}

uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    if (mod == 0) {
        throw std::invalid_argument("Modulus cannot be zero");
    }
    
    uint64_t result = 1;
    base %= mod;
    
    while (exp > 0) {
        if (exp & 1) {
            result = (static_cast<unsigned __int128>(result) * base) % mod;
        }
        base = (static_cast<unsigned __int128>(base) * base) % mod;
        exp >>= 1;
    }
    
    return result;
}

uint64_t mod_inverse(uint64_t a, uint64_t m) {
    if (gcd(a, m) != 1) {
        throw std::invalid_argument("Modular inverse does not exist");
    }

    int64_t m0 = m;
    int64_t y = 0;
    int64_t x = 1;
    
    while (a > 1) {
        int64_t q = a / m;
        int64_t t = m;
        
        m = a % m;
        a = t;
        t = y;
        
        y = x - q * y;
        x = t;
    }
    
    if (x < 0) {
        x += m0;
    }
    
    return static_cast<uint64_t>(x);
}

bool is_prime(uint64_t n) {
    if (n <= 3) {
        return n > 1;
    }
    
    if (n % 2 == 0 || n % 3 == 0) {
        return false;
    }
    
    // Miller-Rabin primality test
    const int num_trials = 5;  // Number of trials for probabilistic primality
    
    // Find r and d such that n = 2^r * d + 1
    uint64_t d = n - 1;
    int r = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        r++;
    }
    
    // Witness loop
    for (int i = 0; i < num_trials; i++) {
        uint64_t a = random_uint64(2, n - 2);
        uint64_t x = mod_pow(a, d, n);
        
        if (x == 1 || x == n - 1) {
            continue;
        }
        
        bool is_composite = true;
        for (int j = 0; j < r - 1; j++) {
            x = mod_pow(x, 2, n);
            if (x == n - 1) {
                is_composite = false;
                break;
            }
        }
        
        if (is_composite) {
            return false;
        }
    }
    
    return true;
}

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }
    
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }
    
    return bytes;
}

} // namespace crypto::utils