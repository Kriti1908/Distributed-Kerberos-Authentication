#pragma once
#include "bigint.h"
#include "crypto_utils.h"
#include <string>
#include <vector>
#include <array>
#include <cstdint>

// ─────────────────────────────────────────────────────────────────────────────
//  Independent Schnorr Multi-Signature
//
//  Parameters: p, q, g where q | (p-1), g has order q in Z_p*
//  Each authority has independent keypair: x_i in Zq, y_i = g^{x_i} mod p
//
//  Signing protocol for authority i:
//    k_i <- rand(Zq), R_i = g^{k_i} mod p
//    e_i = H(msg || R_i || authorityID) mod q
//    s_i = k_i + e_i * x_i mod q
//    Signature is (R_i, s_i, authorityID)
//
//  Verification:
//    e_i = H(msg || R_i || authorityID) mod q
//    g^{s_i} == R_i * y_i^{e_i} mod p
// ─────────────────────────────────────────────────────────────────────────────

struct SchnorrParams {
    BigInt p, q, g;

    std::string toHex() const;
    static SchnorrParams fromHex(const std::string& s);

    void save(const std::string& filename) const;
    static SchnorrParams load(const std::string& filename);
};

struct KeyShare {
    int    index;   // authority ID
    BigInt xi;      // private key x_i

    void save(const std::string& filename) const;
    static KeyShare load(const std::string& filename);
};

struct AuthoritySignature {
    int    authorityID;
    BigInt R;
    BigInt s;
};

// ─────────────────────────────────────────────────────────────────────────────
class MultiSchnorr {
public:
    // ── Setup ────────────────────────────────────────────────────────────────
    // Generate Schnorr parameters (p ~512 bit, q ~256 bit)
    static SchnorrParams generateParams();

    // Generate independent private key
    static BigInt generatePrivateKey(const SchnorrParams& params);

    // ── Per-authority operations ─────────────────────────────────────────────
    // Sign a message: returns (R, s, authorityID)
    static AuthoritySignature sign(const std::vector<uint8_t>& msg,
                                   int authorityID,
                                   const BigInt& x,
                                   const SchnorrParams& params);

    // Compute challenge: e = H(msg || R || authorityID)
    static BigInt computeChallenge(const std::vector<uint8_t>& msg,
                                   const BigInt& R,
                                   int authorityID,
                                   const BigInt& q);

    // ── Verification ────────────────────────────────────────────────────────
    // Verify a single authority's signature: g^s == R * y^e (mod p)
    static bool verify(const AuthoritySignature& sig,
                       const std::vector<uint8_t>& msg,
                       const BigInt& y,
                       const SchnorrParams& params);
};

// ── Serialisation helpers ────────────────────────────────────────────────────
std::string signatureToHex(const AuthoritySignature& sig);
AuthoritySignature signatureFromHex(const std::string& hex);
