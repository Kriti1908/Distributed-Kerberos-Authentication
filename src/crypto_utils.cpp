#include "include/crypto_utils.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <cstdint>

#ifdef _WIN32
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "Bcrypt.lib")
#else
  #include <fstream>
#endif

// ═════════════════════════════════════════════════════════════════════════════
//  SHA-256  – FIPS 180-4 compliant manual implementation
// ═════════════════════════════════════════════════════════════════════════════
namespace {

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t ROTR(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t SHR (uint32_t x, int n) { return x >> n; }
inline uint32_t CH  (uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t MAJ (uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t EP0 (uint32_t x) { return ROTR(x,2)^ROTR(x,13)^ROTR(x,22); }
inline uint32_t EP1 (uint32_t x) { return ROTR(x,6)^ROTR(x,11)^ROTR(x,25); }
inline uint32_t SIG0(uint32_t x) { return ROTR(x,7)^ROTR(x,18)^SHR(x,3);  }
inline uint32_t SIG1(uint32_t x) { return ROTR(x,17)^ROTR(x,19)^SHR(x,10); }

void sha256Block(const uint8_t block[64], uint32_t H[8]) {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i)
        W[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
    for (int i = 16; i < 64; ++i)
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];

    uint32_t a=H[0],b=H[1],c=H[2],d=H[3],
             e=H[4],f=H[5],g=H[6],h=H[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + EP1(e) + CH(e,f,g) + K256[i] + W[i];
        uint32_t t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d;
    H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
}

} // anonymous

SHA256::Digest SHA256::hash(const uint8_t* data, size_t len) {
    uint32_t H[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    // Process full blocks
    size_t i = 0;
    uint8_t block[64];
    for (; i + 64 <= len; i += 64)
        sha256Block(data + i, H);

    // Padding
    size_t rem = len - i;
    memcpy(block, data + i, rem);
    block[rem++] = 0x80;
    if (rem > 56) {
        memset(block + rem, 0, 64 - rem);
        sha256Block(block, H);
        rem = 0;
    }
    memset(block + rem, 0, 56 - rem);
    uint64_t bitlen = (uint64_t)len * 8;
    block[56]=(uint8_t)(bitlen>>56); block[57]=(uint8_t)(bitlen>>48);
    block[58]=(uint8_t)(bitlen>>40); block[59]=(uint8_t)(bitlen>>32);
    block[60]=(uint8_t)(bitlen>>24); block[61]=(uint8_t)(bitlen>>16);
    block[62]=(uint8_t)(bitlen>>8);  block[63]=(uint8_t)(bitlen);
    sha256Block(block, H);

    Digest out;
    for (int j = 0; j < 8; ++j) {
        out[j*4+0] = (H[j]>>24)&0xFF;
        out[j*4+1] = (H[j]>>16)&0xFF;
        out[j*4+2] = (H[j]>>8) &0xFF;
        out[j*4+3] =  H[j]     &0xFF;
    }
    return out;
}

SHA256::Digest SHA256::hash(const std::string& s) {
    return hash(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

SHA256::Digest SHA256::hash(const std::vector<uint8_t>& v) {
    return hash(v.data(), v.size());
}

std::string SHA256::hexdigest(const Digest& d) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : d) oss << std::setw(2) << (int)b;
    return oss.str();
}

SHA256::Digest SHA256::hashConcat(const std::vector<uint8_t>& a,
                                   const std::vector<uint8_t>& b) {
    std::vector<uint8_t> c;
    c.insert(c.end(), a.begin(), a.end());
    c.insert(c.end(), b.begin(), b.end());
    return hash(c);
}

// ═════════════════════════════════════════════════════════════════════════════
//  AES-256-CBC  –  FIPS 197 manual implementation
// ═════════════════════════════════════════════════════════════════════════════
namespace {

// AES S-box
static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// AES Inverse S-box  
static const uint8_t INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

// RCON table
static const uint8_t RCON[11] = {
    0x00, 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

} // anonymous

// ── GF(2^8) multiply ─────────────────────────────────────────────────────────
uint8_t AES256CBC::gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        bool hb = (a & 0x80) != 0;
        a <<= 1;
        if (hb) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

uint32_t AES256CBC::subWord(uint32_t w) {
    return ((uint32_t)SBOX[(w>>24)&0xFF]<<24)|((uint32_t)SBOX[(w>>16)&0xFF]<<16)|
           ((uint32_t)SBOX[(w>>8) &0xFF]<<8) |(uint32_t)SBOX[w&0xFF];
}

uint32_t AES256CBC::rotWord(uint32_t w) {
    return (w << 8) | (w >> 24);
}

// ── Key Expansion for AES-256 (14 rounds, 60 words) ─────────────────────────
void AES256CBC::keyExpansion(const uint8_t* key, RoundKeys& rk) {
    for (int i = 0; i < 8; ++i)
        rk[i] = ((uint32_t)key[4*i]<<24)|((uint32_t)key[4*i+1]<<16)|
                ((uint32_t)key[4*i+2]<<8)|(uint32_t)key[4*i+3];
    for (int i = 8; i < 60; ++i) {
        uint32_t t = rk[i-1];
        if (i % 8 == 0)       t = subWord(rotWord(t)) ^ ((uint32_t)RCON[i/8] << 24);
        else if (i % 8 == 4)  t = subWord(t);
        rk[i] = rk[i-8] ^ t;
    }
}

// ── SubBytes / InvSubBytes ───────────────────────────────────────────────────
void AES256CBC::subBytes(Block& b) {
    for (auto& x : b) x = SBOX[x];
}
void AES256CBC::invSubBytes(Block& b) {
    for (auto& x : b) x = INV_SBOX[x];
}

// ── ShiftRows / InvShiftRows  (column-major order: state[col][row]) ─────────
// We use row-major here: state is [row][col], i.e. block[row*4+col]
void AES256CBC::shiftRows(Block& b) {
    // Row 1: left shift 1
    { uint8_t t=b[1]; b[1]=b[5]; b[5]=b[9]; b[9]=b[13]; b[13]=t; }
    // Row 2: left shift 2
    { uint8_t t=b[2]; b[2]=b[10]; b[10]=t; t=b[6]; b[6]=b[14]; b[14]=t; }
    // Row 3: left shift 3 (= right shift 1)
    { uint8_t t=b[15]; b[15]=b[11]; b[11]=b[7]; b[7]=b[3]; b[3]=t; }
}

void AES256CBC::invShiftRows(Block& b) {
    // Row 1: right shift 1
    { uint8_t t=b[13]; b[13]=b[9]; b[9]=b[5]; b[5]=b[1]; b[1]=t; }
    // Row 2: right shift 2
    { uint8_t t=b[2]; b[2]=b[10]; b[10]=t; t=b[6]; b[6]=b[14]; b[14]=t; }
    // Row 3: right shift 3 (= left shift 1)
    { uint8_t t=b[3]; b[3]=b[7]; b[7]=b[11]; b[11]=b[15]; b[15]=t; }
}

// ── MixColumns / InvMixColumns ───────────────────────────────────────────────
void AES256CBC::mixColumns(Block& b) {
    for (int c = 0; c < 4; ++c) {
        uint8_t s0=b[c], s1=b[4+c], s2=b[8+c], s3=b[12+c];
        b[c]   = gmul(0x02,s0)^gmul(0x03,s1)^s2^s3;
        b[4+c] = s0^gmul(0x02,s1)^gmul(0x03,s2)^s3;
        b[8+c] = s0^s1^gmul(0x02,s2)^gmul(0x03,s3);
        b[12+c]= gmul(0x03,s0)^s1^s2^gmul(0x02,s3);
    }
}

void AES256CBC::invMixColumns(Block& b) {
    for (int c = 0; c < 4; ++c) {
        uint8_t s0=b[c], s1=b[4+c], s2=b[8+c], s3=b[12+c];
        b[c]   = gmul(0x0e,s0)^gmul(0x0b,s1)^gmul(0x0d,s2)^gmul(0x09,s3);
        b[4+c] = gmul(0x09,s0)^gmul(0x0e,s1)^gmul(0x0b,s2)^gmul(0x0d,s3);
        b[8+c] = gmul(0x0d,s0)^gmul(0x09,s1)^gmul(0x0e,s2)^gmul(0x0b,s3);
        b[12+c]= gmul(0x0b,s0)^gmul(0x0d,s1)^gmul(0x09,s2)^gmul(0x0e,s3);
    }
}

// ── Block encrypt / decrypt ──────────────────────────────────────────────────
void AES256CBC::encryptBlock(const Block& in, Block& out, const RoundKeys& rk) {
    Block state = in;
    // AddRoundKey – round 0
    for (int i = 0; i < 16; ++i)
        state[i] ^= (rk[i/4] >> (24 - 8*(i%4))) & 0xFF;

    for (int round = 1; round <= 14; ++round) {
        subBytes(state);
        shiftRows(state);
        if (round < 14) mixColumns(state);
        for (int i = 0; i < 16; ++i)
            state[i] ^= (rk[round*4 + i/4] >> (24 - 8*(i%4))) & 0xFF;
    }
    out = state;
}

void AES256CBC::decryptBlock(const Block& in, Block& out, const RoundKeys& rk) {
    Block state = in;
    // AddRoundKey – round 14
    for (int i = 0; i < 16; ++i)
        state[i] ^= (rk[14*4 + i/4] >> (24 - 8*(i%4))) & 0xFF;

    for (int round = 13; round >= 0; --round) {
        invShiftRows(state);
        invSubBytes(state);
        for (int i = 0; i < 16; ++i)
            state[i] ^= (rk[round*4 + i/4] >> (24 - 8*(i%4))) & 0xFF;
        if (round > 0) invMixColumns(state);
    }
    out = state;
}

// ── PKCS#7 padding ────────────────────────────────────────────────────────────
std::vector<uint8_t> AES256CBC::pkcs7Pad(const std::vector<uint8_t>& data, size_t bs) {
    size_t pad = bs - (data.size() % bs);
    std::vector<uint8_t> out = data;
    out.insert(out.end(), pad, static_cast<uint8_t>(pad));
    return out;
}

std::vector<uint8_t> AES256CBC::pkcs7Unpad(const std::vector<uint8_t>& data) {
    if (data.empty()) throw std::runtime_error("pkcs7Unpad: empty data");
    uint8_t pad = data.back();
    if (pad == 0 || pad > 16) throw std::runtime_error("pkcs7Unpad: invalid padding");
    for (size_t i = data.size() - pad; i < data.size(); ++i)
        if (data[i] != pad) throw std::runtime_error("pkcs7Unpad: bad padding byte");
    return std::vector<uint8_t>(data.begin(), data.end() - pad);
}

// ── Public API ────────────────────────────────────────────────────────────────
std::vector<uint8_t> AES256CBC::encrypt(const std::vector<uint8_t>& plaintext,
                                         const std::vector<uint8_t>& key,
                                         const std::vector<uint8_t>& iv) {
    if (key.size() != KEY_SIZE) throw std::invalid_argument("AES256CBC: key must be 32 bytes");
    if (iv.size()  != IV_SIZE ) throw std::invalid_argument("AES256CBC: iv must be 16 bytes");

    RoundKeys rk;
    keyExpansion(key.data(), rk);

    auto padded = pkcs7Pad(plaintext, BLOCK_SIZE);
    std::vector<uint8_t> out(padded.size());
    Block prev;
    memcpy(prev.data(), iv.data(), BLOCK_SIZE);

    for (size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
        Block blk;
        for (size_t j = 0; j < BLOCK_SIZE; ++j) blk[j] = padded[i+j] ^ prev[j];
        Block enc;
        encryptBlock(blk, enc, rk);
        prev = enc;
        memcpy(out.data() + i, enc.data(), BLOCK_SIZE);
    }
    return out;
}

std::vector<uint8_t> AES256CBC::decrypt(const std::vector<uint8_t>& ciphertext,
                                         const std::vector<uint8_t>& key,
                                         const std::vector<uint8_t>& iv) {
    if (key.size()  != KEY_SIZE ) throw std::invalid_argument("AES256CBC: key must be 32 bytes");
    if (iv.size()   != IV_SIZE  ) throw std::invalid_argument("AES256CBC: iv must be 16 bytes");
    if (ciphertext.size() % BLOCK_SIZE != 0)
        throw std::invalid_argument("AES256CBC: ciphertext not block-aligned");

    RoundKeys rk;
    keyExpansion(key.data(), rk);

    std::vector<uint8_t> out(ciphertext.size());
    Block prev;
    memcpy(prev.data(), iv.data(), BLOCK_SIZE);

    for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE) {
        Block blk, dec;
        memcpy(blk.data(), ciphertext.data() + i, BLOCK_SIZE);
        decryptBlock(blk, dec, rk);
        for (size_t j = 0; j < BLOCK_SIZE; ++j) out[i+j] = dec[j] ^ prev[j];
        prev = blk;
    }
    return pkcs7Unpad(out);
}

std::vector<uint8_t> AES256CBC::encryptWithIV(const std::vector<uint8_t>& plaintext,
                                               const std::vector<uint8_t>& key) {
    auto iv = randomIV();
    auto enc = encrypt(plaintext, key, iv);
    std::vector<uint8_t> out;
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), enc.begin(), enc.end());
    return out;
}

std::vector<uint8_t> AES256CBC::decryptWithIV(const std::vector<uint8_t>& data,
                                               const std::vector<uint8_t>& key) {
    if (data.size() < IV_SIZE + BLOCK_SIZE)
        throw std::runtime_error("AES256CBC::decryptWithIV: data too short");
    std::vector<uint8_t> iv(data.begin(), data.begin() + IV_SIZE);
    std::vector<uint8_t> ct(data.begin() + IV_SIZE, data.end());
    return decrypt(ct, key, iv);
}

std::vector<uint8_t> AES256CBC::randomKey() { return CryptoUtils::randomBytes(KEY_SIZE); }
std::vector<uint8_t> AES256CBC::randomIV()  { return CryptoUtils::randomBytes(IV_SIZE);  }

// ═════════════════════════════════════════════════════════════════════════════
//  CryptoUtils
// ═════════════════════════════════════════════════════════════════════════════
std::vector<uint8_t> CryptoUtils::randomBytes(size_t n) {
    std::vector<uint8_t> buf(n);
#ifdef _WIN32
    if (BCryptGenRandom(nullptr, buf.data(), (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("CryptoUtils::randomBytes: BCryptGenRandom failed");
#else
    std::ifstream f("/dev/urandom", std::ios::binary);
    if (!f) throw std::runtime_error("CryptoUtils::randomBytes: cannot open /dev/urandom");
    f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)n);
    if (f.gcount() != (std::streamsize)n)
        throw std::runtime_error("CryptoUtils::randomBytes: short read from /dev/urandom");
#endif
    return buf;
}

std::string CryptoUtils::bytesToHex(const std::vector<uint8_t>& b) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto x : b) oss << std::setw(2) << (int)x;
    return oss.str();
}

std::vector<uint8_t> CryptoUtils::hexToBytes(const std::string& hex) {
    if (hex.size() % 2) throw std::invalid_argument("hexToBytes: odd length");
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = (uint8_t)std::stoi(hex.substr(2*i, 2), nullptr, 16);
    return out;
}

static const char B64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string CryptoUtils::bytesToBase64(const std::vector<uint8_t>& b) {
    std::string out;
    size_t i = 0;
    while (i + 2 < b.size()) {
        uint32_t v = ((uint32_t)b[i]<<16)|((uint32_t)b[i+1]<<8)|b[i+2];
        out += B64_CHARS[(v>>18)&63]; out += B64_CHARS[(v>>12)&63];
        out += B64_CHARS[(v>>6) &63]; out += B64_CHARS[v&63];
        i += 3;
    }
    if (i < b.size()) {
        uint32_t v = (uint32_t)b[i] << 16;
        if (i+1 < b.size()) v |= (uint32_t)b[i+1] << 8;
        out += B64_CHARS[(v>>18)&63]; out += B64_CHARS[(v>>12)&63];
        out += (i+1 < b.size()) ? B64_CHARS[(v>>6)&63] : '=';
        out += '=';
    }
    return out;
}

std::vector<uint8_t> CryptoUtils::base64ToBytes(const std::string& s) {
    auto val = [](char c) -> int {
        if (c>='A'&&c<='Z') return c-'A';
        if (c>='a'&&c<='z') return c-'a'+26;
        if (c>='0'&&c<='9') return c-'0'+52;
        if (c=='+') return 62;
        if (c=='/') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 3 < s.size(); i += 4) {
        int a=val(s[i]),b=val(s[i+1]),c=val(s[i+2]),d=val(s[i+3]);
        if (a<0||b<0) break;
        out.push_back((uint8_t)((a<<2)|(b>>4)));
        if (c>=0) out.push_back((uint8_t)((b<<4)|(c>>2)));
        if (d>=0) out.push_back((uint8_t)((c<<6)|d));
    }
    return out;
}

std::vector<uint8_t> CryptoUtils::deriveKey(const std::string& password,
                                              const std::vector<uint8_t>& salt,
                                              size_t iterations) {
    // Simple PBKDF2-like: hash(password || salt) iterated
    std::vector<uint8_t> data;
    data.insert(data.end(), password.begin(), password.end());
    data.insert(data.end(), salt.begin(), salt.end());
    auto d = SHA256::hash(data);
    std::vector<uint8_t> k(d.begin(), d.end());
    for (size_t i = 1; i < iterations; ++i) {
        auto nd = SHA256::hash(k);
        k.assign(nd.begin(), nd.end());
    }
    return k;
}
