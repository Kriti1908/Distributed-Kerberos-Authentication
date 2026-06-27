/*
 * client.cpp
 *
 * Kerberos Independent Multi-Schnorr Client
 */

#include "include/bigint.h"
#include "include/crypto_utils.h"
#include "include/schnorr.h"
#include "include/ticket.h"
#include "include/network.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <stdexcept>
#include <ctime>

static const std::vector<uint16_t> DEFAULT_AS_PORTS  = {8001, 8002, 8003};
static const std::vector<uint16_t> DEFAULT_TGS_PORTS = {8101, 8102, 8103};
static const char*                 AS_HOST            = "127.0.0.1";
static const char*                 TGS_HOST           = "127.0.0.1";
static const char*                 SVC_HOST           = "127.0.0.1";
static const uint16_t              DEFAULT_SVC_PORT   = 9001;

struct ASResponse {
    int                  nodeID;
    int                  keyVersion;
    std::string          requestID;
    std::vector<uint8_t> encSessionKey;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> encryptedTicket;
    std::vector<uint8_t> signedBytes;
    AuthoritySignature   sig;
};

struct TGSResponse {
    int                  nodeID;
    int                  keyVersion;
    std::string          requestID;
    std::vector<uint8_t> encSvcSessionKey;
    std::vector<uint8_t> encryptedTicket;
    std::vector<uint8_t> signedBytes;
    AuthoritySignature   sig;
};

class KerberosClient {
public:
    KerberosClient(const std::string& username, const std::string& password,
                   const std::vector<uint16_t>& asPorts,
                   const std::vector<uint16_t>& tgsPorts,
                   const std::string& configDir = "config")
        : username_(username), password_(password),
          asPorts_(asPorts), tgsPorts_(tgsPorts),
          configDir_(configDir)
    {}

    bool init() {
        try {
            params_ = SchnorrParams::load(configDir_ + "/params.txt");
        } catch (const std::exception& e) {
            std::cerr << "[Client] Cannot load params: " << e.what() << "\n";
            return false;
        }

        for (int i = 1; i <= 3; ++i) {
            std::ifstream asf(configDir_ + "/as_pubkey_" + std::to_string(i) + ".txt");
            if (asf) { std::string hex; asf >> hex; asPubKeys_[i] = BigInt(hex); }
            
            std::ifstream tgsf(configDir_ + "/tgs_pubkey_" + std::to_string(i) + ".txt");
            if (tgsf) { std::string hex; tgsf >> hex; tgsPubKeys_[i] = BigInt(hex); }
        }

        return true;
    }

    bool authenticate(const std::string& serviceID,
                      uint16_t svcPort = DEFAULT_SVC_PORT) {
        std::cout << "\n=== Phase 1: AS Exchange (get TGT) ===\n";
        if (!runASExchange()) return false;

        std::cout << "\n=== Phase 2: TGS Exchange (get Service Ticket) ===\n";
        if (!runTGSExchange(serviceID)) return false;

        std::cout << "\n=== Phase 3: Service Authentication ===\n";
        if (!runServiceAuth(serviceID, svcPort)) return false;

        return true;
    }

    const Ticket&                 getTGT()           const { return tgt_; }
    const Ticket&                 getServiceTicket() const { return serviceTicket_; }
    const std::vector<uint8_t>&   getTGTSessionKey() const { return tgtSessionKey_; }
    const std::vector<uint8_t>&   getSvcSessionKey() const { return svcSessionKey_; }

private:
    std::string username_, password_;
    std::vector<uint16_t> asPorts_, tgsPorts_;
    std::string configDir_;

    SchnorrParams params_;
    std::map<int, BigInt> asPubKeys_;
    std::map<int, BigInt> tgsPubKeys_;

    Ticket              tgt_;
    Ticket              serviceTicket_;
    std::vector<uint8_t> tgtSessionKey_;
    std::vector<uint8_t> svcSessionKey_;

    static std::string genRequestID() {
        auto bytes = CryptoUtils::randomBytes(16);
        return CryptoUtils::bytesToHex(bytes);
    }

    bool runASExchange() {
        std::string reqID = genRequestID();
        std::vector<ASResponse> responses;

        int64_t issueTime = std::time(nullptr);

        for (size_t i = 0; i < asPorts_.size(); ++i) {
            ASResponse resp;
            resp.requestID = reqID;

            TCPClient client;
            if (!client.connect(AS_HOST, asPorts_[i])) {
                std::cout << "[Client] AS" << (i+1) << " unreachable, skipping.\n";
                continue;
            }

            Message req = Message::build("AUTH_REQ", {
                username_, password_, reqID, "krbtgt", std::to_string(issueTime)
            });
            Message respMsg;
            if (!client.exchange(req, respMsg)) {
                std::cout << "[Client] No response from AS" << (i+1) << "\n";
                continue;
            }
            client.disconnect();

            if (respMsg.type != "AUTH_RESP") {
                std::cout << "[Client] AS" << (i+1) << " denied: "
                          << (respMsg.fields.empty() ? "?" : respMsg.get(0)) << "\n";
                continue;
            }
            if (respMsg.fields.size() < 8) {
                std::cout << "[Client] AS" << (i+1) << " malformed AUTH_RESP.\n";
                continue;
            }

            try {
                resp.nodeID          = std::stoi(respMsg.get(0));
                resp.keyVersion      = std::stoi(respMsg.get(1));
                resp.requestID       = respMsg.get(2);
                resp.encSessionKey   = CryptoUtils::hexToBytes(respMsg.get(3));
                resp.salt            = CryptoUtils::hexToBytes(respMsg.get(4));
                resp.encryptedTicket = CryptoUtils::hexToBytes(respMsg.get(5));
                resp.signedBytes     = CryptoUtils::base64ToBytes(respMsg.get(6));
                resp.sig             = signatureFromHex(respMsg.get(7));
            } catch (...) {
                std::cout << "[Client] AS" << (i + 1) << " sent malformed AUTH_RESP data.\n";
                continue;
            }
            if (resp.requestID != reqID) {
                std::cout << "[Client] Ignoring AUTH_RESP with mismatched request ID from AS"
                          << (i + 1) << "\n";
                continue;
            }

            std::cout << "[Client] Got AUTH_RESP from AS" << resp.nodeID
                      << " (keyVer=" << resp.keyVersion << ")\n";
            responses.push_back(resp);
        }

        if (responses.size() < 2) {
            std::cerr << "[Client] Need at least 2 AS responses, got "
                      << responses.size() << "\n";
            return false;
        }
        
        for (const auto& r : responses) {
            if (r.signedBytes != responses[0].signedBytes) {
                std::cerr << "[Client] ERROR: AS nodes returned different signed payloads!\n";
                return false;
            }
            if (r.keyVersion != responses[0].keyVersion) {
                std::cerr << "[Client] ERROR: AS nodes returned different key versions!\n";
                return false;
            }
        }

        std::vector<AuthoritySignature> sigs;
        for (const auto& r : responses) sigs.push_back(r.sig);

        std::set<int> validAuthorities;
        for (const auto& sig : sigs) {
            if (validAuthorities.count(sig.authorityID)) continue;
            if (asPubKeys_.find(sig.authorityID) != asPubKeys_.end()) {
                if (MultiSchnorr::verify(sig, responses[0].signedBytes, asPubKeys_[sig.authorityID], params_)) {
                    validAuthorities.insert(sig.authorityID);
                }
            }
        }

        if (validAuthorities.size() < 2) {
            std::cerr << "[Client] TGT signature verification FAILED! distinct valid signatures="
                      << validAuthorities.size() << "\n";
            return false;
        }
        std::cout << "[Client] TGT threshold signature VERIFIED.\n";

        auto clientKey = CryptoUtils::deriveKey(password_, responses[0].salt, 1000);
        tgtSessionKey_ = AES256CBC::decryptWithIV(responses[0].encSessionKey, clientKey);
        std::cout << "[Client] TGT session key decrypted.\n";

        tgt_ = Ticket{
            responses[0].encryptedTicket,
            sigs,
            responses[0].keyVersion,
            TicketType::TGT,
            responses[0].signedBytes
        };

        std::cout << "[Client] TGT assembled.\n";
        std::cout << "[Client] TGT keyVersion=" << tgt_.keyVersion << "\n";
        return true;
    }

    bool runTGSExchange(const std::string& serviceID) {
        std::string reqID = genRequestID();
        Authenticator auth = TicketFactory::buildAuthenticator(username_, tgtSessionKey_);
        std::string tgtSer = tgt_.serialise();

        std::vector<TGSResponse> responses;

        for (size_t i = 0; i < tgsPorts_.size(); ++i) {
            TGSResponse resp;
            resp.requestID = reqID;

            TCPClient client;
            if (!client.connect(TGS_HOST, tgsPorts_[i])) {
                std::cout << "[Client] TGS" << (i+1) << " unreachable.\n";
                continue;
            }

            Message req = Message::build("TGS_REQ", {
                username_,
                serviceID,
                CryptoUtils::bytesToBase64(std::vector<uint8_t>(tgtSer.begin(), tgtSer.end())),
                auth.serialise(),
                reqID,
            });
            Message respMsg;
            if (!client.exchange(req, respMsg) || respMsg.type != "TGS_RESP") {
                std::cout << "[Client] TGS" << (i+1) << " rejected: "
                          << (respMsg.fields.empty() ? "?" : respMsg.get(0)) << "\n";
                continue;
            }
            if (respMsg.fields.size() < 7) {
                std::cout << "[Client] TGS" << (i+1) << " malformed TGS_RESP.\n";
                continue;
            }
            client.disconnect();

            try {
                resp.nodeID           = std::stoi(respMsg.get(0));
                resp.keyVersion       = std::stoi(respMsg.get(1));
                resp.requestID        = respMsg.get(2);
                resp.encSvcSessionKey = CryptoUtils::hexToBytes(respMsg.get(3));
                resp.encryptedTicket  = CryptoUtils::hexToBytes(respMsg.get(4));
                resp.signedBytes      = CryptoUtils::base64ToBytes(respMsg.get(5));
                resp.sig              = signatureFromHex(respMsg.get(6));
            } catch (...) {
                std::cout << "[Client] TGS" << (i + 1) << " sent malformed TGS_RESP data.\n";
                continue;
            }
            if (resp.requestID != reqID) {
                std::cout << "[Client] Ignoring TGS_RESP with mismatched request ID from TGS"
                          << (i + 1) << "\n";
                continue;
            }

            std::cout << "[Client] Got TGS_RESP from TGS" << resp.nodeID << "\n";
            responses.push_back(resp);
        }

        if (responses.size() < 2) {
            std::cerr << "[Client] Need at least 2 TGS responses\n";
            return false;
        }

        for (const auto& r : responses) {
            if (r.signedBytes != responses[0].signedBytes) {
                std::cerr << "[Client] ERROR: TGS nodes returned different signed payloads!\n";
                return false;
            }
            if (r.keyVersion != responses[0].keyVersion) {
                std::cerr << "[Client] ERROR: TGS nodes returned different key versions!\n";
                return false;
            }
        }

        std::vector<AuthoritySignature> sigs;
        for (const auto& r : responses) sigs.push_back(r.sig);

        std::set<int> validAuthorities;
        for (const auto& sig : sigs) {
            if (validAuthorities.count(sig.authorityID)) continue;
            if (tgsPubKeys_.find(sig.authorityID) != tgsPubKeys_.end()) {
                if (MultiSchnorr::verify(sig, responses[0].signedBytes, tgsPubKeys_[sig.authorityID], params_)) {
                    validAuthorities.insert(sig.authorityID);
                }
            }
        }

        if (validAuthorities.size() < 2) {
            std::cerr << "[Client] Service ticket signature FAILED! distinct valid signatures="
                      << validAuthorities.size() << "\n";
            return false;
        }
        std::cout << "[Client] Service ticket threshold signature VERIFIED.\n";

        svcSessionKey_ = AES256CBC::decryptWithIV(responses[0].encSvcSessionKey, tgtSessionKey_);
        std::cout << "[Client] Service session key decrypted.\n";

        serviceTicket_.encryptedPayload = responses[0].encryptedTicket;
        serviceTicket_.signatures       = sigs;
        serviceTicket_.keyVersion       = responses[0].keyVersion;
        serviceTicket_.type             = TicketType::SERVICE;
        serviceTicket_.signedBytes      = responses[0].signedBytes;

        std::cout << "[Client] Service ticket assembled.\n";
        return true;
    }

    bool runServiceAuth(const std::string&, uint16_t svcPort) {
        TCPClient client;
        if (!client.connect(SVC_HOST, svcPort)) {
            std::cerr << "[Client] Cannot connect to service on port " << svcPort << "\n";
            return false;
        }

        Authenticator auth = TicketFactory::buildAuthenticator(username_, svcSessionKey_);

        Message req = Message::build("SERVICE_REQ", {
            username_,
            serviceTicket_.serialise(),
            auth.serialise(),
        });
        Message resp;
        if (!client.exchange(req, resp)) {
            std::cerr << "[Client] No response from service\n";
            return false;
        }

        if (resp.type == "SVC_OK") {
            std::cout << "[Client] Service says: " << resp.get(2) << "\n";
            client.disconnect();
            return true;
        } else {
            std::cerr << "[Client] Service denied: "
                      << (resp.fields.empty() ? "?" : resp.get(0)) << "\n";
            client.disconnect();
            return false;
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: client <username> <password> <service_id> "
                     "[--as-ports 8001,8002,8003] "
                     "[--tgs-ports 8101,8102,8103] "
                     "[--svc-port 9001]\n";
        return 1;
    }

    std::string username   = argv[1];
    std::string password   = argv[2];
    std::string serviceID  = argv[3];

    std::vector<uint16_t> asPorts  = DEFAULT_AS_PORTS;
    std::vector<uint16_t> tgsPorts = DEFAULT_TGS_PORTS;
    uint16_t              svcPort  = DEFAULT_SVC_PORT;

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--as-ports" && i+1 < argc) {
            asPorts.clear();
            std::istringstream ss(argv[++i]);
            std::string t;
            while (std::getline(ss, t, ',')) asPorts.push_back((uint16_t)std::stoi(t));
        } else if (arg == "--tgs-ports" && i+1 < argc) {
            tgsPorts.clear();
            std::istringstream ss(argv[++i]);
            std::string t;
            while (std::getline(ss, t, ',')) tgsPorts.push_back((uint16_t)std::stoi(t));
        } else if (arg == "--svc-port" && i+1 < argc) {
            svcPort = (uint16_t)std::stoi(argv[++i]);
        }
    }

    if (!netInit()) { std::cerr << "Network init failed\n"; return 1; }

    KerberosClient kclient(username, password, asPorts, tgsPorts);
    if (!kclient.init()) return 1;

    bool ok = kclient.authenticate(serviceID, svcPort);
    std::cout << "\n[Client] Authentication "
              << (ok ? "SUCCEEDED" : "FAILED") << "\n";

    netCleanup();
    return ok ? 0 : 1;
}
