#pragma once
#include "crypto_utils.h"
#include "schnorr.h"
#include <string>
#include <vector>
#include <cstdint>
#include <ctime>

// ─────────────────────────────────────────────────────────────────────────────
//  Ticket types and structures
// ─────────────────────────────────────────────────────────────────────────────

enum class TicketType { TGT, SERVICE };

// ── Plain-text ticket payload (before encryption) ───────────────────────────
struct TicketPayload {
    std::string   clientID;
    std::string   serviceID;
    int64_t       issueTimestamp = 0;   // Unix epoch seconds
    int64_t       lifetime = 0;         // seconds
    std::vector<uint8_t> sessionKey;  // 32-byte AES-256 key
    std::string   authorityMetadata;  // JSON: which authorities signed, etc.
    int           keyVersion = 0;
    TicketType    type = TicketType::TGT;

    // Serialise to/from byte vector for signing and encryption
    std::vector<uint8_t> serialise()   const;
    static TicketPayload deserialise(const std::vector<uint8_t>& data);

    bool isExpired() const;
    bool isValid()   const;
};

// ── Full ticket (encrypted payload + threshold signature) ───────────────────
struct Ticket {
    // Encrypted payload: AES-256-CBC(serialise(payload), sessionKey, IV)
    std::vector<uint8_t> encryptedPayload;
    std::vector<AuthoritySignature> signatures;
    int                  keyVersion = 0;
    TicketType           type = TicketType::TGT;

    // For verification: we keep the plaintext bytes that were signed
    // (the hash of these is the challenge input)
    std::vector<uint8_t> signedBytes;

    std::string serialise()   const;
    static Ticket deserialise(const std::string& data);
};

// ── Authenticator (client-generated, proves ticket ownership) ────────────────
struct Authenticator {
    std::string   clientID;
    int64_t       timestamp = 0;     // must be fresh (within 5 min of server time)
    std::vector<uint8_t> nonce;      // random nonce to avoid replay collisions
    std::vector<uint8_t> mac;        // HMAC-SHA256(clientID||timestamp, sessionKey)

    std::string serialise()   const;
    static Authenticator deserialise(const std::string& s);

    bool isFresh(int windowSeconds = 300) const;
};

// ── Session ─────────────────────────────────────────────────────────────────
struct Session {
    std::string   clientID;
    std::string   serviceID;
    std::vector<uint8_t> sessionKey;
    int64_t       expiry = 0;

    bool isExpired() const;
};

// ─────────────────────────────────────────────────────────────────────────────
//  TicketFactory  –  creates and validates tickets
// ─────────────────────────────────────────────────────────────────────────────
class TicketFactory {
public:
    static constexpr int64_t TGT_LIFETIME     = 8 * 3600;   // 8 hours
    static constexpr int64_t SERVICE_LIFETIME = 1 * 3600;   // 1 hour

    // Build the plaintext bytes to be signed (and later encrypted)
    static std::vector<uint8_t> buildSignedBytes(const TicketPayload& p);

    // Encrypt payload with a server-side master key (for storage)
    // key must be 32 bytes; returns IV-prepended ciphertext
    static std::vector<uint8_t> encryptPayload(const TicketPayload& p,
                                               const std::vector<uint8_t>& key);

    // Decrypt and deserialise
    static TicketPayload decryptPayload(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& key);

    // Verify the MAC in an authenticator against the session key
    static bool verifyAuthenticator(const Authenticator& auth,
                                    const std::vector<uint8_t>& sessionKey);

    // Build authenticator
    static Authenticator buildAuthenticator(const std::string& clientID,
                                            const std::vector<uint8_t>& sessionKey);
};
