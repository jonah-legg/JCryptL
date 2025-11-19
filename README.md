# JCryptL

This is a bare-bones mathematical encryption library for educational purposes only. It processes data byte-by-byte and implements basic encryption protocols

## WARNING: DO NOT USE IN PRODUCTION

This implementation is **NOT** secure and should **NOT** be used for actual encryption. It lacks:
- Proper padding (vulnerable to padding oracle attacks)
- Adequate key sizes (uses small keys that can be broken)

For real applications, use cryptographic libraries like OpenSSL, Libsodium, among others.

## Usage Example

```cpp
// Generate key pair
auto keys = crypto::KeyGenerator::generate_rsa();
    
// Original message
std::string message = "Test Message 123";
std::vector<uint8_t> data(message.begin(), message.end());
    
// Encrypt
auto encrypted = encrypt(data, keys.public_key);
    
// Decrypt
auto decrypted = decrypt(data, keys.private_key);

// Print decrypted message
std::cout std::string(decrypted.begin(), decrypted.end());
```

## Test Script

A test script is located in `src/main.cpp`