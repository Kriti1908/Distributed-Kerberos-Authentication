#include "include/bigint.h"
#include <cassert>
#include <stdexcept>
#include <sstream>
#include <cctype>
#include <cstring>

#ifdef _WIN32
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "Bcrypt.lib")
#else
  #include <fstream>
#endif

// ─────────────────────────────────────────────────────────────────────────────
//  Constructors
// ─────────────────────────────────────────────────────────────────────────────
BigInt::BigInt() { d.push_back(0); }

BigInt::BigInt(uint64_t v) {
    d.push_back(static_cast<limb_t>(v & 0xFFFFFFFFu));
    limb_t hi = static_cast<limb_t>(v >> 32);
    if (hi) d.push_back(hi);
    if (d.empty()) d.push_back(0);
}

BigInt::BigInt(const std::string& hex) {
    d.clear();
    std::string h = hex;
    // strip leading zeros from string
    size_t start = h.find_first_not_of('0');
    if (start == std::string::npos) { d.push_back(0); return; }
    h = h.substr(start);
    // parse in 8-char (32-bit) chunks from the right
    for (int i = (int)h.size(); i > 0; i -= 8) {
        int beg = std::max(0, i - 8);
        std::string chunk = h.substr(beg, i - beg);
        d.push_back(static_cast<limb_t>(std::stoul(chunk, nullptr, 16)));
    }
    trim();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Trim leading zero limbs
// ─────────────────────────────────────────────────────────────────────────────
void BigInt::trim() {
    while (d.size() > 1 && d.back() == 0) d.pop_back();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Conversions
// ─────────────────────────────────────────────────────────────────────────────
std::string BigInt::toHex() const {
    if (isZero()) return "0";
    std::ostringstream oss;
    oss << std::hex;
    for (int i = (int)d.size() - 1; i >= 0; --i) {
        if (i == (int)d.size() - 1)
            oss << d[i];            // no padding on MSW
        else
            oss << std::setw(8) << std::setfill('0') << d[i];
    }
    return oss.str();
}

std::string BigInt::toDec() const {
    if (isZero()) return "0";
    std::string result;
    BigInt tmp = *this;
    BigInt ten(10u);
    while (!tmp.isZero()) {
        BigInt rem;
        BigInt::divmod(tmp, ten, rem);
        result += static_cast<char>('0' + rem.toU64());
        tmp = tmp / ten;
    }
    std::reverse(result.begin(), result.end());
    return result;
}

uint64_t BigInt::toU64() const {
    uint64_t v = d[0];
    if (d.size() > 1) v |= (static_cast<uint64_t>(d[1]) << 32);
    return v;
}

bool BigInt::isZero() const {
    for (auto x : d) if (x) return false;
    return true;
}

size_t BigInt::bits() const {
    for (int i = (int)d.size() - 1; i >= 0; --i) {
        if (d[i]) {
            size_t b = (size_t)i * 32;
            limb_t lim = d[i];
            while (lim) { ++b; lim >>= 1; }
            return b;
        }
    }
    return 0;
}

bool BigInt::bit(size_t i) const {
    size_t limb = i / 32, off = i % 32;
    if (limb >= d.size()) return false;
    return (d[limb] >> off) & 1;
}

std::vector<uint8_t> BigInt::toBytes() const {
    size_t nbytes = (bits() + 7) / 8;
    if (nbytes == 0) nbytes = 1;
    std::vector<uint8_t> out(nbytes, 0);
    for (size_t i = 0; i < nbytes; ++i) {
        size_t limb = i / 4, off = (i % 4) * 8;
        if (limb < d.size()) out[nbytes - 1 - i] = (d[limb] >> off) & 0xFF;
    }
    return out;
}

BigInt BigInt::fromBytes(const std::vector<uint8_t>& b) {
    std::string hex;
    for (auto byte : b) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        hex += buf;
    }
    return hex.empty() ? BigInt(0u) : BigInt(hex);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Comparison
// ─────────────────────────────────────────────────────────────────────────────
int BigInt::compare(const BigInt& rhs) const {
    const auto& a = d;
    const auto& b = rhs.d;
    size_t n = std::max(a.size(), b.size());
    for (int i = (int)n - 1; i >= 0; --i) {
        limb_t ai = (size_t)i < a.size() ? a[i] : 0;
        limb_t bi = (size_t)i < b.size() ? b[i] : 0;
        if (ai < bi) return -1;
        if (ai > bi) return  1;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Addition
// ─────────────────────────────────────────────────────────────────────────────
BigInt BigInt::operator+(const BigInt& rhs) const {
    BigInt res;
    res.d.resize(std::max(d.size(), rhs.d.size()) + 1, 0);
    dlimb_t carry = 0;
    for (size_t i = 0; i < res.d.size(); ++i) {
        dlimb_t ai = i < d.size()     ? d[i]     : 0;
        dlimb_t bi = i < rhs.d.size() ? rhs.d[i] : 0;
        dlimb_t s  = ai + bi + carry;
        res.d[i] = static_cast<limb_t>(s);
        carry    = s >> 32;
    }
    res.trim();
    return res;
}

BigInt& BigInt::operator+=(const BigInt& rhs) { *this = *this + rhs; return *this; }

// ─────────────────────────────────────────────────────────────────────────────
//  Subtraction  (self >= rhs assumed)
// ─────────────────────────────────────────────────────────────────────────────
BigInt BigInt::operator-(const BigInt& rhs) const {
    if (*this < rhs) throw std::underflow_error("BigInt subtraction underflow");
    BigInt res;
    res.d.resize(d.size(), 0);
    int64_t borrow = 0;
    for (size_t i = 0; i < d.size(); ++i) {
        int64_t ai = d[i];
        int64_t bi = i < rhs.d.size() ? rhs.d[i] : 0;
        int64_t diff = ai - bi - borrow;
        if (diff < 0) { diff += (int64_t)1 << 32; borrow = 1; }
        else borrow = 0;
        res.d[i] = static_cast<limb_t>(diff);
    }
    res.trim();
    return res;
}

BigInt& BigInt::operator-=(const BigInt& rhs) { *this = *this - rhs; return *this; }

// ─────────────────────────────────────────────────────────────────────────────
//  Multiplication  (schoolbook)
// ─────────────────────────────────────────────────────────────────────────────
BigInt BigInt::operator*(const BigInt& rhs) const {
    BigInt res;
    res.d.assign(d.size() + rhs.d.size(), 0);
    for (size_t i = 0; i < d.size(); ++i) {
        dlimb_t carry = 0;
        for (size_t j = 0; j < rhs.d.size(); ++j) {
            dlimb_t cur = (dlimb_t)d[i] * rhs.d[j] + res.d[i + j] + carry;
            res.d[i + j] = static_cast<limb_t>(cur);
            carry = cur >> 32;
        }
        res.d[i + rhs.d.size()] += static_cast<limb_t>(carry);
    }
    res.trim();
    return res;
}

BigInt& BigInt::operator*=(const BigInt& rhs) { *this = *this * rhs; return *this; }

// ─────────────────────────────────────────────────────────────────────────────
//  Left / Right shift
// ─────────────────────────────────────────────────────────────────────────────
BigInt BigInt::operator<<(unsigned bits) const {
    if (isZero()) return *this;
    unsigned limbShift = bits / 32, bitShift = bits % 32;
    BigInt res;
    res.d.assign(d.size() + limbShift + 1, 0);
    for (size_t i = 0; i < d.size(); ++i) {
        res.d[i + limbShift] |= d[i] << bitShift;
        if (bitShift && i + limbShift + 1 < res.d.size())
            res.d[i + limbShift + 1] |= (dlimb_t)d[i] >> (32 - bitShift);
    }
    res.trim();
    return res;
}

BigInt BigInt::operator>>(unsigned bits) const {
    unsigned limbShift = bits / 32, bitShift = bits % 32;
    if (limbShift >= d.size()) return BigInt(0u);
    BigInt res;
    res.d.assign(d.size() - limbShift, 0);
    for (size_t i = limbShift; i < d.size(); ++i) {
        res.d[i - limbShift] = d[i] >> bitShift;
        if (bitShift && i + 1 < d.size())
            res.d[i - limbShift] |= (dlimb_t)d[i + 1] << (32 - bitShift);
    }
    res.trim();
    return res;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Division and remainder  (Knuth Algorithm D, simplified)
// ─────────────────────────────────────────────────────────────────────────────
BigInt BigInt::divmod(const BigInt& a, const BigInt& b, BigInt& rem) {
    if (b.isZero()) throw std::domain_error("BigInt: division by zero");
    if (a < b) { rem = a; return BigInt(0u); }

    // long division bit-by-bit (simple but correct for any size)
    BigInt quotient(0u);
    rem = BigInt(0u);
    for (int i = (int)a.bits() - 1; i >= 0; --i) {
        rem = rem << 1;
        if (a.bit((size_t)i)) rem.d[0] |= 1;
        if (rem >= b) {
            rem -= b;
            // set bit i in quotient
            if (quotient.d.size() <= (size_t)i / 32)
                quotient.d.resize((size_t)i / 32 + 1, 0);
            quotient.d[(size_t)i / 32] |= (1u << ((size_t)i % 32));
        }
    }
    quotient.trim();
    return quotient;
}

BigInt BigInt::operator/(const BigInt& rhs) const { BigInt r; return divmod(*this, rhs, r); }
BigInt BigInt::operator%(const BigInt& rhs) const { BigInt r; divmod(*this, rhs, r); return r; }
BigInt& BigInt::operator%=(const BigInt& rhs) { *this = *this % rhs; return *this; }

// ─────────────────────────────────────────────────────────────────────────────
//  GCD
// ─────────────────────────────────────────────────────────────────────────────
BigInt BigInt::gcd(const BigInt& a, const BigInt& b) {
    BigInt x = a, y = b;
    while (!y.isZero()) { BigInt t = x % y; x = y; y = t; }
    return x;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Modular arithmetic
// ─────────────────────────────────────────────────────────────────────────────
BigInt BigInt::addMod(const BigInt& b, const BigInt& m) const {
    BigInt r = (*this + b) % m;
    return r;
}

BigInt BigInt::subMod(const BigInt& b, const BigInt& m) const {
    // Handle underflow: (a - b) mod m = (a + m - b) mod m
    if (*this >= b) return (*this - b) % m;
    return (m - (b - *this) % m) % m;
}

BigInt BigInt::mulMod(const BigInt& b, const BigInt& m) const {
    return (*this * b) % m;
}

// Fast modular exponentiation  (binary method)
BigInt BigInt::powMod(const BigInt& e, const BigInt& m) const {
    if (m == BigInt(1u)) return BigInt(0u);
    BigInt result(1u);
    BigInt base = *this % m;
    size_t nbits = e.bits();
    for (size_t i = 0; i < nbits; ++i) {
        if (e.bit(i)) result = result.mulMod(base, m);
        base = base.mulMod(base, m);
    }
    return result;
}

// Modular inverse via extended Euclidean
// Returns x such that a*x ≡ 1 (mod m), assumes gcd(a,m)=1
BigInt BigInt::invMod(const BigInt& m) const {
    // Extended Euclidean: work with signed BigInts via a flag
    // We use the iterative version
    if (m == BigInt(1u)) return BigInt(0u);

    // Represent signed values as (BigInt magnitude, bool negative)
    BigInt old_r = *this % m, r = m;
    BigInt old_s(1u), s(0u);
    bool old_s_neg = false, s_neg = false;

    while (!r.isZero()) {
        BigInt rem;
        BigInt q = divmod(old_r, r, rem);

        BigInt new_r = rem;
        // new_s = old_s - q * s  (signed)
        BigInt qs = q * s;
        bool new_s_neg;
        BigInt new_s;
        if (old_s_neg == s_neg) {
            // same sign: new_s = |old_s - q*s|, sign = old_s_neg if old_s > q*s else !old_s_neg
            if (old_s >= qs) { new_s = old_s - qs; new_s_neg = old_s_neg; }
            else             { new_s = qs - old_s; new_s_neg = !old_s_neg; }
        } else {
            // different signs: new_s = old_s + q*s, sign = old_s_neg
            new_s = old_s + qs; new_s_neg = old_s_neg;
        }

        old_r = r;  r = new_r;
        old_s = s;  old_s_neg = s_neg;
        s = new_s;  s_neg = new_s_neg;
    }

    if (old_r != BigInt(1u)) throw std::runtime_error("BigInt::invMod: not invertible");
    if (old_s_neg) return m - old_s % m;
    return old_s % m;
}

// ─────────────────────────────────────────────────────────────────────────────
//  randomInRange  –  uniform random in [0, mod-1]
// ─────────────────────────────────────────────────────────────────────────────
BigInt randomInRange(const BigInt& mod) {
    if (mod.isZero()) throw std::invalid_argument("randomInRange: mod must be > 0");
    size_t nbytes = (mod.bits() + 7) / 8 + 1;

#ifdef _WIN32
    std::vector<uint8_t> buf(nbytes);
    BCryptGenRandom(nullptr, buf.data(), (ULONG)buf.size(),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    std::vector<uint8_t> buf(nbytes);
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    urandom.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
#endif

    BigInt r = BigInt::fromBytes(buf);
    return r % mod;
}
