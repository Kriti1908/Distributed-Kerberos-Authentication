#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <array>

// ─────────────────────────────────────────────────────────────────────────────
//  SHA-256  (manual, no libraries)
// ─────────────────────────────────────────────────────────────────────────────
class SHA256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;
    using Digest = std::array<uint8_t, DIGEST_SIZE>;

    static Digest hash(const uint8_t* data, size_t len);
    static Digest hash(const std::string& s);
    static Digest hash(const std::vector<uint8_t>& v);

    // Hex string from digest
    static std::string hexdigest(const Digest& d);
    // Combine two hash inputs: H(a || b)
    static Digest hashConcat(const std::vector<uint8_t>& a,
                             const std::vector<uint8_t>& b);
};

// ─────────────────────────────────────────────────────────────────────────────
//  AES-256-CBC  (manual, with PKCS#7 padding)
// ─────────────────────────────────────────────────────────────────────────────
class AES256CBC {
public:
    static constexpr size_t KEY_SIZE   = 32;
    static constexpr size_t BLOCK_SIZE = 16;
    static constexpr size_t IV_SIZE    = 16;

    // Both key and iv must be exactly KEY_SIZE / IV_SIZE bytes
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv);

    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv);

    // Convenience: generates a random IV and prepends it to the output
    static std::vector<uint8_t> encryptWithIV(const std::vector<uint8_t>& plaintext,
                                               const std::vector<uint8_t>& key);

    // Expects first IV_SIZE bytes to be the IV
    static std::vector<uint8_t> decryptWithIV(const std::vector<uint8_t>& data,
                                               const std::vector<uint8_t>& key);

    static std::vector<uint8_t> randomKey();
    static std::vector<uint8_t> randomIV();

private:
    // AES internals
    using Block = std::array<uint8_t, BLOCK_SIZE>;
    using RoundKeys = std::array<uint32_t, 60>;

    static void     keyExpansion(const uint8_t* key, RoundKeys& rk);
    static void     encryptBlock(const Block& in, Block& out, const RoundKeys& rk);
    static void     decryptBlock(const Block& in, Block& out, const RoundKeys& rk);
    static void     subBytes   (Block& b);
    static void     invSubBytes(Block& b);
    static void     shiftRows  (Block& b);
    static void     invShiftRows(Block& b);
    static void     mixColumns (Block& b);
    static void     invMixColumns(Block& b);
    static uint8_t  gmul(uint8_t a, uint8_t b);
    static uint32_t subWord(uint32_t w);
    static uint32_t rotWord(uint32_t w);

    // PKCS#7
    static std::vector<uint8_t> pkcs7Pad  (const std::vector<uint8_t>& data, size_t bs);
    static std::vector<uint8_t> pkcs7Unpad(const std::vector<uint8_t>& data);
};

// ─────────────────────────────────────────────────────────────────────────────
//  Utility helpers
// ─────────────────────────────────────────────────────────────────────────────
namespace CryptoUtils {
    std::vector<uint8_t> randomBytes(size_t n);
    std::string          bytesToHex(const std::vector<uint8_t>& b);
    std::vector<uint8_t> hexToBytes(const std::string& hex);
    std::string          bytesToBase64(const std::vector<uint8_t>& b);
    std::vector<uint8_t> base64ToBytes(const std::string& s);
    // Derive AES key from password+salt via iterated SHA-256
    std::vector<uint8_t> deriveKey(const std::string& password,
                                   const std::vector<uint8_t>& salt,
                                   size_t iterations = 1000);
}
