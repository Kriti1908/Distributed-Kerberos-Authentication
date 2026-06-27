#include "include/ticket.h"
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <ctime>

// ─────────────────────────────────────────────────────────────────────────────
//  Simple key-value line serialiser used by TicketPayload and Authenticator
// ─────────────────────────────────────────────────────────────────────────────
namespace {

void writeLine(std::ostream& os, const std::string& key, const std::string& val) {
    os << key << "=" << val << "\n";
}

std::string readVal(const std::string& line) {
    auto p = line.find('=');
    if (p == std::string::npos) return "";
    return line.substr(p + 1);
}

// Tiny HMAC-SHA256:  HMAC(k, m) = H( (k^opad) || H( (k^ipad) || m ) )
SHA256::Digest hmacSHA256(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& msg) {
    const size_t BLOCK = 64;
    std::vector<uint8_t> k(BLOCK, 0);
    if (key.size() > BLOCK) {
        auto hk = SHA256::hash(key);
        std::copy(hk.begin(), hk.end(), k.begin());
    } else {
        std::copy(key.begin(), key.end(), k.begin());
    }
    std::vector<uint8_t> ipad(BLOCK), opad(BLOCK);
    for (size_t i = 0; i < BLOCK; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }
    std::vector<uint8_t> inner;
    inner.insert(inner.end(), ipad.begin(), ipad.end());
    inner.insert(inner.end(), msg.begin(),  msg.end());
    auto ih = SHA256::hash(inner);

    std::vector<uint8_t> outer;
    outer.insert(outer.end(), opad.begin(), opad.end());
    outer.insert(outer.end(), ih.begin(),   ih.end());
    return SHA256::hash(outer);
}

} // anonymous

// ─────────────────────────────────────────────────────────────────────────────
//  TicketPayload
// ─────────────────────────────────────────────────────────────────────────────
std::vector<uint8_t> TicketPayload::serialise() const {
    std::ostringstream oss;
    writeLine(oss, "clientID",  clientID);
    writeLine(oss, "serviceID", serviceID);
    writeLine(oss, "issue",     std::to_string(issueTimestamp));
    writeLine(oss, "lifetime",  std::to_string(lifetime));
    writeLine(oss, "sessionKey",CryptoUtils::bytesToHex(sessionKey));
    writeLine(oss, "authority", authorityMetadata);
    writeLine(oss, "keyVersion",std::to_string(keyVersion));
    writeLine(oss, "type",      (type == TicketType::TGT ? "TGT" : "SERVICE"));
    std::string s = oss.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

TicketPayload TicketPayload::deserialise(const std::vector<uint8_t>& data) {
    std::string s(data.begin(), data.end());
    std::istringstream iss(s);
    std::string line;
    TicketPayload p;
    while (std::getline(iss, line)) {
        if (line.rfind("clientID=", 0)  == 0) p.clientID  = readVal(line);
        else if (line.rfind("serviceID=",0) == 0) p.serviceID = readVal(line);
        else if (line.rfind("issue=",0)    == 0) p.issueTimestamp = std::stoll(readVal(line));
        else if (line.rfind("lifetime=",0) == 0) p.lifetime       = std::stoll(readVal(line));
        else if (line.rfind("sessionKey=",0)==0) p.sessionKey = CryptoUtils::hexToBytes(readVal(line));
        else if (line.rfind("authority=",0)==0)  p.authorityMetadata = readVal(line);
        else if (line.rfind("keyVersion=",0)==0) p.keyVersion = std::stoi(readVal(line));
        else if (line.rfind("type=",0)     == 0)
            p.type = (readVal(line) == "TGT") ? TicketType::TGT : TicketType::SERVICE;
    }
    return p;
}

bool TicketPayload::isExpired() const {
    return std::time(nullptr) > (issueTimestamp + lifetime);
}

bool TicketPayload::isValid() const {
    return !clientID.empty() &&
           !serviceID.empty() &&
           sessionKey.size() == AES256CBC::KEY_SIZE &&
           lifetime > 0 &&
           keyVersion > 0 &&
           !isExpired();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Ticket
// ─────────────────────────────────────────────────────────────────────────────
std::string Ticket::serialise() const {
    std::ostringstream oss;
    writeLine(oss, "enc",        CryptoUtils::bytesToBase64(encryptedPayload));
    for(size_t i=0;i<signatures.size();i++)
    {
        writeLine(oss,"sig"+std::to_string(i),
                signatureToHex(signatures[i]));
    }
    writeLine(oss, "keyVersion", std::to_string(keyVersion));
    writeLine(oss, "type",       (type == TicketType::TGT ? "TGT" : "SERVICE"));
    writeLine(oss, "signed",     CryptoUtils::bytesToBase64(signedBytes));
    return oss.str();
}

Ticket Ticket::deserialise(const std::string& data) {
    std::istringstream iss(data);
    std::string line;
    Ticket t;
    while (std::getline(iss, line)) {
        if      (line.rfind("enc=",        0)==0) t.encryptedPayload = CryptoUtils::base64ToBytes(readVal(line));
        else if(line.rfind("sig",0)==0 && line.rfind("signed=",0)!=0) t.signatures.push_back(signatureFromHex(readVal(line)));
        else if (line.rfind("keyVersion=", 0)==0) t.keyVersion       = std::stoi(readVal(line));
        else if (line.rfind("type=",       0)==0)
            t.type = (readVal(line) == "TGT") ? TicketType::TGT : TicketType::SERVICE;
        else if (line.rfind("signed=",     0)==0) t.signedBytes = CryptoUtils::base64ToBytes(readVal(line));
    }
    return t;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Authenticator
// ─────────────────────────────────────────────────────────────────────────────
std::string Authenticator::serialise() const {
    std::ostringstream oss;
    writeLine(oss, "clientID",  clientID);
    writeLine(oss, "timestamp", std::to_string(timestamp));
    writeLine(oss, "nonce",     CryptoUtils::bytesToHex(nonce));
    writeLine(oss, "mac",       CryptoUtils::bytesToHex(mac));
    return oss.str();
}

Authenticator Authenticator::deserialise(const std::string& s) {
    std::istringstream iss(s);
    std::string line;
    Authenticator a;
    while (std::getline(iss, line)) {
        if      (line.rfind("clientID=", 0)==0)  a.clientID  = readVal(line);
        else if (line.rfind("timestamp=",0)==0)  a.timestamp = std::stoll(readVal(line));
        else if (line.rfind("nonce=",    0)==0)  a.nonce     = CryptoUtils::hexToBytes(readVal(line));
        else if (line.rfind("mac=",      0)==0)  a.mac       = CryptoUtils::hexToBytes(readVal(line));
    }
    return a;
}

bool Authenticator::isFresh(int window) const {
    int64_t now = (int64_t)std::time(nullptr);
    return std::abs(now - timestamp) <= window;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Session
// ─────────────────────────────────────────────────────────────────────────────
bool Session::isExpired() const {
    return std::time(nullptr) > expiry;
}

// ─────────────────────────────────────────────────────────────────────────────
//  TicketFactory
// ─────────────────────────────────────────────────────────────────────────────
std::vector<uint8_t> TicketFactory::buildSignedBytes(const TicketPayload& p) {
    // Bind signature to the session key via its hash without exposing the key itself.
    auto skHash = SHA256::hash(p.sessionKey);
    std::ostringstream oss;
    oss << p.clientID << "\n"
        << p.serviceID << "\n"
        << p.issueTimestamp << "\n"
        << p.lifetime << "\n"
        << SHA256::hexdigest(skHash) << "\n"
        << p.keyVersion << "\n"
        << (p.type == TicketType::TGT ? "TGT" : "SERVICE") << "\n"
        << p.authorityMetadata;
    std::string s = oss.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> TicketFactory::encryptPayload(const TicketPayload& p,
                                                    const std::vector<uint8_t>& key) {
    auto bytes = p.serialise();
    return AES256CBC::encryptWithIV(bytes, key);
}

TicketPayload TicketFactory::decryptPayload(const std::vector<uint8_t>& ciphertext,
                                             const std::vector<uint8_t>& key) {
    auto bytes = AES256CBC::decryptWithIV(ciphertext, key);
    return TicketPayload::deserialise(bytes);
}

bool TicketFactory::verifyAuthenticator(const Authenticator& auth,
                                         const std::vector<uint8_t>& sessionKey) {
    if (!auth.isFresh()) return false;
    if (auth.nonce.empty()) return false;
    // Recompute MAC = HMAC-SHA256(sessionKey, clientID || "|" || timestamp || "|" || nonceHex)
    std::string data = auth.clientID + "|" + std::to_string(auth.timestamp) + "|" +
                       CryptoUtils::bytesToHex(auth.nonce);
    std::vector<uint8_t> d(data.begin(), data.end());
    auto expected = hmacSHA256(sessionKey, d);
    if (auth.mac.size() != expected.size()) return false;
    // Constant-time compare
    uint8_t diff = 0;
    for (size_t i = 0; i < expected.size(); ++i)
        diff |= auth.mac[i] ^ expected[i];
    return diff == 0;
}

Authenticator TicketFactory::buildAuthenticator(const std::string& clientID,
                                                 const std::vector<uint8_t>& sessionKey) {
    Authenticator auth;
    auth.clientID  = clientID;
    auth.timestamp = (int64_t)std::time(nullptr);
    auth.nonce     = CryptoUtils::randomBytes(16);
    std::string data = clientID + "|" + std::to_string(auth.timestamp) + "|" +
                       CryptoUtils::bytesToHex(auth.nonce);
    std::vector<uint8_t> d(data.begin(), data.end());
    auto h = hmacSHA256(sessionKey, d);
    auth.mac = std::vector<uint8_t>(h.begin(), h.end());
    return auth;
}
