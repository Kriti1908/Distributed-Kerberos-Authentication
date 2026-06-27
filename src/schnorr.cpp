#include "include/schnorr.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstring>

// ─────────────────────────────────────────────────────────────────────────────
//  SchnorrParams  –  serialisation
// ─────────────────────────────────────────────────────────────────────────────
std::string SchnorrParams::toHex() const {
    return p.toHex() + "|" + q.toHex() + "|" + g.toHex();
}

SchnorrParams SchnorrParams::fromHex(const std::string& s) {
    std::istringstream ss(s);
    std::string ps, qs, gs;
    std::getline(ss, ps, '|');
    std::getline(ss, qs, '|');
    std::getline(ss, gs, '|');
    SchnorrParams out;
    out.p = BigInt(ps); out.q = BigInt(qs); out.g = BigInt(gs);
    return out;
}

void SchnorrParams::save(const std::string& filename) const {
    std::ofstream f(filename);
    if (!f) throw std::runtime_error("Cannot write " + filename);
    f << toHex() << "\n";
}

SchnorrParams SchnorrParams::load(const std::string& filename) {
    std::ifstream f(filename);
    if (!f) throw std::runtime_error("Cannot read " + filename);
    std::string line;
    std::getline(f, line);
    return fromHex(line);
}

// ─────────────────────────────────────────────────────────────────────────────
//  KeyShare  –  serialisation
// ─────────────────────────────────────────────────────────────────────────────
void KeyShare::save(const std::string& filename) const {
    std::ofstream f(filename);
    if (!f) throw std::runtime_error("Cannot write " + filename);
    f << index << "|" << xi.toHex() << "\n";
}

KeyShare KeyShare::load(const std::string& filename) {
    std::ifstream f(filename);
    if (!f) throw std::runtime_error("Cannot read " + filename);
    std::string line;
    std::getline(f, line);
    auto pos = line.find('|');
    if (pos == std::string::npos) throw std::runtime_error("Invalid share file");
    KeyShare ks;
    ks.index = std::stoi(line.substr(0, pos));
    ks.xi    = BigInt(line.substr(pos + 1));
    return ks;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Miller-Rabin primality test
// ─────────────────────────────────────────────────────────────────────────────
static bool millerRabinRound(const BigInt& n, const BigInt& a,
                              const BigInt& d, uint64_t r) {
    BigInt x = a.powMod(d, n);
    BigInt one(1u), nm1 = n - one;
    if (x == one || x == nm1) return true;
    for (uint64_t i = 0; i < r - 1; ++i) {
        x = x.mulMod(x, n);
        if (x == nm1) return true;
    }
    return false;
}

static bool isPrime(const BigInt& n, int rounds = 20) {
    if (n < BigInt(2u)) return false;
    if (n == BigInt(2u) || n == BigInt(3u)) return true;
    if (n.bit(0) == 0) return false;  // even

    // Write n-1 = 2^r * d
    BigInt d = n - BigInt(1u);
    uint64_t r = 0;
    while (d.bit(0) == 0) { d = d >> 1; ++r; }

    static const uint64_t witnesses[] = {2,3,5,7,11,13,17,19,23,29,31,37};
    for (int i = 0; i < rounds && i < 12; ++i) {
        BigInt a(witnesses[i]);
        if (a >= n) continue;
        if (!millerRabinRound(n, a, d, r)) return false;
    }
    for (int i = 12; i < rounds; ++i) {
        BigInt a = randomInRange(n - BigInt(3u)) + BigInt(2u);
        if (!millerRabinRound(n, a, d, r)) return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Generate Schnorr parameters  (p ~512 bit, q ~256 bit, q | p-1)
// ─────────────────────────────────────────────────────────────────────────────
SchnorrParams MultiSchnorr::generateParams() {
    BigInt q;
    do {
        auto bytes = CryptoUtils::randomBytes(32);
        bytes[0]  |= 0xC0;
        bytes[31] |= 0x01;
        q = BigInt::fromBytes(bytes);
    } while (!isPrime(q, 25));

    BigInt p;
    BigInt two(2u);
    BigInt k = two;
    int attempts = 0;
    do {
        if (++attempts > 10000) throw std::runtime_error("generateParams: failed to find p");
        auto kbytes = CryptoUtils::randomBytes(32);
        kbytes[0]  |= 0x80;
        kbytes[31] &= 0xFE;
        k = BigInt::fromBytes(kbytes);
        if (k.bit(0)) k = k + BigInt(1u);
        p = k * q + BigInt(1u);
    } while (!isPrime(p, 20));

    BigInt g;
    BigInt exp_val = (p - BigInt(1u)) / q;
    do {
        BigInt h = randomInRange(p - BigInt(2u)) + BigInt(2u);
        g = h.powMod(exp_val, p);
    } while (g == BigInt(1u));

    SchnorrParams params;
    params.p = p;
    params.q = q;
    params.g = g;
    return params;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Generate private key
// ─────────────────────────────────────────────────────────────────────────────
BigInt MultiSchnorr::generatePrivateKey(const SchnorrParams& params) {
    if (params.q <= BigInt(1u)) throw std::runtime_error("generatePrivateKey: invalid q");
    return randomInRange(params.q - BigInt(1u)) + BigInt(1u);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Compute challenge  e = H(msg || R || authorityID) mod q
// ─────────────────────────────────────────────────────────────────────────────
BigInt MultiSchnorr::computeChallenge(const std::vector<uint8_t>& msg,
                                       const BigInt& R,
                                       int authorityID,
                                       const BigInt& q) {
    auto rbytes = R.toBytes();
    std::string id_str = std::to_string(authorityID);
    
    std::vector<uint8_t> data;
    data.insert(data.end(), msg.begin(), msg.end());
    data.insert(data.end(), rbytes.begin(), rbytes.end());
    data.insert(data.end(), id_str.begin(), id_str.end());
    
    auto h = SHA256::hash(data);
    BigInt e = BigInt::fromBytes(std::vector<uint8_t>(h.begin(), h.end()));
    return e % q;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Sign: returns (R, s, authorityID)
// ─────────────────────────────────────────────────────────────────────────────
AuthoritySignature MultiSchnorr::sign(const std::vector<uint8_t>& msg,
                                      int authorityID,
                                      const BigInt& x,
                                      const SchnorrParams& params) {
    if (params.q <= BigInt(1u)) throw std::runtime_error("sign: invalid q");
    BigInt k = randomInRange(params.q - BigInt(1u)) + BigInt(1u);
    BigInt R = params.g.powMod(k, params.p);
    BigInt e = computeChallenge(msg, R, authorityID, params.q);
    BigInt s = k.addMod(e.mulMod(x, params.q), params.q);

    AuthoritySignature sig;
    sig.authorityID = authorityID;
    sig.R = R;
    sig.s = s;
    return sig;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Verify:  g^s ≡ R · y^e  (mod p)
// ─────────────────────────────────────────────────────────────────────────────
bool MultiSchnorr::verify(const AuthoritySignature& sig,
                          const std::vector<uint8_t>& msg,
                          const BigInt& y,
                          const SchnorrParams& params) {
    BigInt e   = computeChallenge(msg, sig.R, sig.authorityID, params.q);
    BigInt lhs = params.g.powMod(sig.s, params.p);
    BigInt ye  = y.powMod(e, params.p);
    BigInt rhs = sig.R.mulMod(ye, params.p);
    return lhs == rhs;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Serialisation helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string signatureToHex(const AuthoritySignature& sig) {
    return std::to_string(sig.authorityID) + ":" + sig.R.toHex() + ":" + sig.s.toHex();
}

AuthoritySignature signatureFromHex(const std::string& hex) {
    auto pos1 = hex.find(':');
    if (pos1 == std::string::npos) throw std::runtime_error("signatureFromHex: bad format 1");
    auto pos2 = hex.find(':', pos1 + 1);
    if (pos2 == std::string::npos) throw std::runtime_error("signatureFromHex: bad format 2");

    AuthoritySignature sig;
    sig.authorityID = std::stoi(hex.substr(0, pos1));
    sig.R = BigInt(hex.substr(pos1 + 1, pos2 - pos1 - 1));
    sig.s = BigInt(hex.substr(pos2 + 1));
    return sig;
}
