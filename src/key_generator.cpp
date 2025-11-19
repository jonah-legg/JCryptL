#include "key_generator.hpp"
#include "rsa.hpp"
#include "crypto_utils.hpp"
#include <random>
#include <chrono>

namespace crypto {

    RSAKeyPair KeyGenerator::generate_rsa() {
        return rsa::generate_keypair();
    }

}