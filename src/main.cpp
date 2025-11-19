#include "key_generator.hpp"
#include "crypto_utils.hpp"
#include "rsa.hpp"
#include "aes.hpp"
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

void print_key(const crypto::AESKey& key) {
    for (uint8_t byte : key) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(byte);
    }
    std::cout << std::dec;
}

int main() {
    try {
        auto rsa_keys = crypto::KeyGenerator::generate_rsa();
        auto aes_key = crypto::KeyGenerator::generate_aes();

        std::cout << "Generated Keys:\n";
        std::cout << "RSA Public (n,e): " << rsa_keys.pub.n << "," << rsa_keys.pub.e << "\n";
        std::cout << "RSA Private (n,d): " << rsa_keys.priv.n << "," << rsa_keys.priv.d << "\n";
        std::cout << "AES-128 Key: ";
        print_key(aes_key);
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

        std::cout << "AES Test:\n";
        auto aes_encrypted = crypto::aes::encrypt(data, aes_key);
        std::cout << "AES Encrypted: ";
        print_hex(aes_encrypted);
        std::cout << "\n";

        auto aes_decrypted = crypto::aes::decrypt(aes_encrypted, aes_key);
        std::cout << "AES Decrypted: " 
                  << std::string(aes_decrypted.begin(), aes_decrypted.end()) 
                  << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}