#include "key_generator.hpp"
#include "crypto_utils.hpp"
#include "rsa.hpp"
#include <iostream>
#include <iomanip>
#include <stdexcept>

void print_hex(const std::vector<uint8_t>& data) {
    for (uint8_t byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(byte);
    }
    std::cout << std::dec;
}

int main() {
    try {
        auto rsa_keys = crypto::KeyGenerator::generate_rsa();

        std::cout << "Generated Key:\n";
        std::cout << "RSA Public (n,e): " << rsa_keys.pub.n << "," << rsa_keys.pub.e << "\n";
        std::cout << "RSA Private (n,d): " << rsa_keys.priv.n << "," << rsa_keys.priv.d << "\n";
        std::cout << "\n\n";

        std::string message = "Test Message 123";
        std::vector<uint8_t> data(message.begin(), message.end());
        
        std::cout << "Original message: " << message << "\n\n";

        std::cout << "RSA Test:\n";
        auto rsa_encrypted = crypto::rsa::encrypt(data, rsa_keys.pub);
        std::cout << "RSA Encrypted: ";
        print_hex(rsa_encrypted);
        std::cout << "\n";

        auto rsa_decrypted = crypto::rsa::decrypt(rsa_encrypted, rsa_keys.priv);
        std::cout << "RSA Decrypted: " 
                  << std::string(rsa_decrypted.begin(), rsa_decrypted.end()) 
                  << "\n\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}