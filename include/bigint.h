#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>

// ─────────────────────────────────────────────────────────────────────────────
//  BigInt  –  arbitrary-precision unsigned integer with modular arithmetic
//  Representation: little-endian base-2^32 (limbs stored LSW-first)
// ─────────────────────────────────────────────────────────────────────────────
class BigInt {
public:
    using limb_t  = uint32_t;
    using dlimb_t = uint64_t;

    std::vector<limb_t> d;          // digits, d[0] is least-significant

    // ── Constructors ────────────────────────────────────────────────────────
    BigInt();
    explicit BigInt(uint64_t v);
    BigInt(const std::string& hex);   // hex string, no "0x" prefix
    BigInt(const BigInt&)            = default;
    BigInt(BigInt&&)                 = default;
    BigInt& operator=(const BigInt&) = default;
    BigInt& operator=(BigInt&&)      = default;

    // ── Conversions ─────────────────────────────────────────────────────────
    std::string  toHex()  const;
    std::string  toDec()  const;
    uint64_t     toU64()  const;
    bool         isZero() const;
    size_t       bits()   const;           // floor(log2(n))+1, 0 for zero
    std::vector<uint8_t> toBytes() const;  // big-endian byte array
    static BigInt fromBytes(const std::vector<uint8_t>& b);

    // ── Comparison ──────────────────────────────────────────────────────────
    int  compare(const BigInt& rhs) const;
    bool operator==(const BigInt& o) const { return compare(o) == 0; }
    bool operator!=(const BigInt& o) const { return compare(o) != 0; }
    bool operator< (const BigInt& o) const { return compare(o) <  0; }
    bool operator<=(const BigInt& o) const { return compare(o) <= 0; }
    bool operator> (const BigInt& o) const { return compare(o) >  0; }
    bool operator>=(const BigInt& o) const { return compare(o) >= 0; }

    // ── Arithmetic ──────────────────────────────────────────────────────────
    BigInt  operator+(const BigInt& rhs) const;
    BigInt  operator-(const BigInt& rhs) const;   // asserts self >= rhs
    BigInt  operator*(const BigInt& rhs) const;
    BigInt  operator/(const BigInt& rhs) const;
    BigInt  operator%(const BigInt& rhs) const;
    BigInt  operator<<(unsigned bits)    const;
    BigInt  operator>>(unsigned bits)    const;
    BigInt& operator+=(const BigInt& rhs);
    BigInt& operator-=(const BigInt& rhs);
    BigInt& operator*=(const BigInt& rhs);
    BigInt& operator%=(const BigInt& rhs);

    // ── Modular arithmetic ──────────────────────────────────────────────────
    BigInt  addMod (const BigInt& b, const BigInt& m) const;
    BigInt  subMod (const BigInt& b, const BigInt& m) const;
    BigInt  mulMod (const BigInt& b, const BigInt& m) const;
    BigInt  powMod (const BigInt& e, const BigInt& m) const;   // fast exp
    BigInt  invMod (const BigInt& m) const;                    // extended GCD
    static BigInt gcd(const BigInt& a, const BigInt& b);

    // ── Bit access ──────────────────────────────────────────────────────────
    bool bit(size_t i) const;

    // ── Helpers ─────────────────────────────────────────────────────────────
    void trim();  // remove leading zero limbs
    static BigInt divmod(const BigInt& a, const BigInt& b, BigInt& rem);
};

// Random BigInt in [0, mod-1] using OS RNG
BigInt randomInRange(const BigInt& mod);
