#include "include/bigint.h"
#include "include/crypto_utils.h"
#include "include/schnorr.h"
#include "include/ticket.h"
#include "include/network.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <set>
#include <mutex>
#include <thread>
#include <atomic>
#include <csignal>
#include <ctime>

class TGSNode {
public:
    TGSNode(int nodeID, uint16_t port, const std::string& configDir)
        : nodeID_(nodeID), port_(port), configDir_(configDir),
          running_(false), keyVersion_(1)
    {}

    bool init() {
        try {
            params_ = SchnorrParams::load(configDir_ + "/params.txt");
        } catch (const std::exception& e) {
            std::cerr << "[TGS" << nodeID_ << "] Cannot load params: " << e.what() << "\n";
            return false;
        }

        std::string shareFile = configDir_ + "/tgs_share_" + std::to_string(nodeID_) + ".txt";
        try {
            share_ = KeyShare::load(shareFile);
        } catch (const std::exception& e) {
            std::cerr << "[TGS" << nodeID_ << "] Cannot load share: " << e.what() << "\n";
            return false;
        }

        for (int i = 1; i <= 3; ++i) {
            std::ifstream f(configDir_ + "/as_pubkey_" + std::to_string(i) + ".txt");
            if (f) {
                std::string hex;
                f >> hex;
                asPubKeys_[i] = BigInt(hex);
            } else {
                std::cerr << "[TGS" << nodeID_ << "] Warning: Cannot load AS pubkey " << i << "\n";
            }
        }

        loadServices();
        loadKeyVersion();

        if (!server_.bind(port_)) {
            std::cerr << "[TGS" << nodeID_ << "] Cannot bind port " << port_ << "\n";
            return false;
        }
        server_.listen();

        std::cout << "[TGS" << nodeID_ << "] Listening on port " << port_ << "\n";
        std::cout << "[TGS" << nodeID_ << "] keyVersion=" << keyVersion_ << "\n";
        return true;
    }

    void run() {
        running_ = true;
        std::thread rotTimer([this]() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::seconds(ROTATION_INTERVAL));
                rotateKeys();
            }
        });

        server_.run([this](NetworkPeer& peer) { handleClient(peer); });
        running_ = false;
        if (rotTimer.joinable()) rotTimer.detach();
    }

    void stop() { running_ = false; server_.stop(); }

private:
    int         nodeID_;
    uint16_t    port_;
    std::string configDir_;
    std::atomic<bool> running_;

    SchnorrParams params_;      
    std::map<int, BigInt> asPubKeys_;
    KeyShare      share_;
    int           keyVersion_;

    std::set<std::string>     services_;

    TCPServer server_;

    std::map<std::string, int64_t> seenTGTs_;
    std::mutex replayMtx_;

    static constexpr int ROTATION_INTERVAL = 3600;

    void loadServices() {
        std::ifstream f(configDir_ + "/services.txt");
        std::string line;
        while (std::getline(f, line))
            if (!line.empty()) services_.insert(line);
        std::cout << "[TGS" << nodeID_ << "] Loaded " << services_.size() << " services.\n";
    }

    void loadKeyVersion() {
        std::ifstream f(configDir_ + "/key_version.txt");
        if (f) f >> keyVersion_;
    }

    void rotateKeys() {
        std::cout << "[TGS" << nodeID_ << "] Rotating keys...\n";
        try {
            params_     = SchnorrParams::load(configDir_ + "/params.txt");
            share_      = KeyShare::load(configDir_ + "/tgs_share_" +
                                         std::to_string(nodeID_) + ".txt");
            for (int i = 1; i <= 3; ++i) {
                std::ifstream f(configDir_ + "/as_pubkey_" + std::to_string(i) + ".txt");
                if (f) {
                    std::string hex;
                    f >> hex;
                    asPubKeys_[i] = BigInt(hex);
                }
            }
            loadKeyVersion();
        } catch (const std::exception& e) {
            std::cerr << "[TGS" << nodeID_ << "] Key rotation failed: " << e.what() << "\n";
        }
    }

    void handleClient(NetworkPeer& peer) {
        Message req;
        if (!peer.recv(req)) return;

        if      (req.type == "PING")     { peer.send(Message::build("PONG", {std::to_string(nodeID_)})); }
        else if (req.type == "TGS_REQ")  { handleTGSReq (peer, req); }
        else    peer.send(Message::build("ERROR", {"Unknown type: " + req.type}));
    }

    void handleTGSReq(NetworkPeer& peer, const Message& req) {
        if (req.fields.size() < 5) {
            peer.send(Message::build("TGS_FAIL", {"Malformed request"}));
            return;
        }
        const std::string& clientID    = req.fields[0];
        const std::string& serviceID   = req.fields[1];
        const std::string& tgtB64      = req.fields[2];
        const std::string& authStr     = req.fields[3];
        const std::string& requestID   = req.fields[4];

        std::cout << "[TGS" << nodeID_ << "] TGS_REQ from " << clientID
                  << " for service " << serviceID << "\n";

        if (services_.find(serviceID) == services_.end()) {
            peer.send(Message::build("TGS_FAIL", {"Unknown service: " + serviceID}));
            return;
        }

        Ticket tgt;
        try {
            auto tgtBytes = CryptoUtils::base64ToBytes(tgtB64);
            std::string tgtStr(tgtBytes.begin(), tgtBytes.end());
            tgt = Ticket::deserialise(tgtStr);
        } catch (...) {
            peer.send(Message::build("TGS_FAIL", {"Bad TGT format"}));
            return;
        }

        std::cout << "[TGS" << nodeID_ << "] TGT keyVersion read=" << tgt.keyVersion << "\n";

        if (tgt.keyVersion != keyVersion_) {
            peer.send(Message::build("TGS_FAIL",
                {"Outdated key version: " + std::to_string(tgt.keyVersion)}));
            return;
        }

        std::set<int> validAuthorities;
        for (const auto& sig : tgt.signatures) {
            if (validAuthorities.count(sig.authorityID)) continue;
            auto it = asPubKeys_.find(sig.authorityID);
            if (it == asPubKeys_.end()) continue;
            if (MultiSchnorr::verify(sig, tgt.signedBytes, it->second, params_))
                validAuthorities.insert(sig.authorityID);
        }

        if (validAuthorities.size() < 2) {
            std::cout << "TGS [" << nodeID_
                      << "] INVALID ticket: only " << validAuthorities.size()
                      << " distinct valid signatures\n";
            peer.send(Message::build("TGS_FAIL", {"Not enough valid signatures"}));
            return;
        }

        std::vector<uint8_t> serverKey = loadServerKey("as_server_key.bin");
        TicketPayload tgtPayload;
        try {
            tgtPayload = TicketFactory::decryptPayload(tgt.encryptedPayload, serverKey);
        } catch (const std::exception& e) {
            peer.send(Message::build("TGS_FAIL",
                {"Cannot decrypt TGT: " + std::string(e.what())}));
            return;
        }

        auto expectedSignedBytes = TicketFactory::buildSignedBytes(tgtPayload);
        if (expectedSignedBytes != tgt.signedBytes) {
            peer.send(Message::build("TGS_FAIL", {"TGT payload/signature mismatch"}));
            return;
        }
        if (tgtPayload.keyVersion != tgt.keyVersion) {
            peer.send(Message::build("TGS_FAIL", {"TGT key version mismatch"}));
            return;
        }
        if (tgtPayload.clientID != clientID) {
            peer.send(Message::build("TGS_FAIL", {"ClientID mismatch"}));
            return;
        }
        if (tgtPayload.isExpired()) {
            peer.send(Message::build("TGS_FAIL", {"TGT expired"}));
            return;
        }
        if (tgtPayload.type != TicketType::TGT) {
            peer.send(Message::build("TGS_FAIL", {"Not a TGT"}));
            return;
        }

        Authenticator auth;
        try {
            auth = Authenticator::deserialise(authStr);
        } catch (...) {
            peer.send(Message::build("TGS_FAIL", {"Bad authenticator format"}));
            return;
        }
        if (!TicketFactory::verifyAuthenticator(auth, tgtPayload.sessionKey)) {
            peer.send(Message::build("TGS_FAIL", {"Bad authenticator"}));
            return;
        }

        {
            std::lock_guard<std::mutex> lk(replayMtx_);
            std::string tgtID = requestID + "|" + clientID + "|" +
                                std::to_string(auth.timestamp) + "|" +
                                CryptoUtils::bytesToHex(auth.nonce);
            auto rit = seenTGTs_.find(tgtID);
            if (rit != seenTGTs_.end()) {
                peer.send(Message::build("TGS_FAIL", {"Replay detected"}));
                return;
            }
            seenTGTs_[tgtID] = (int64_t)std::time(nullptr);
            for (auto it = seenTGTs_.begin(); it != seenTGTs_.end(); ) {
                if ((int64_t)std::time(nullptr) - it->second > 600)
                    it = seenTGTs_.erase(it);
                else ++it;
            }
        }

        auto serviceKey = loadServerKey("tgs_server_key.bin");
        auto serviceSessionKey = deriveClusterSessionKey(
            serviceKey, requestID, clientID, serviceID, auth.timestamp);
        TicketPayload svcPayload;
        svcPayload.clientID          = clientID;
        svcPayload.serviceID         = serviceID;
        svcPayload.issueTimestamp    = auth.timestamp;
        svcPayload.lifetime          = TicketFactory::SERVICE_LIFETIME;
        svcPayload.sessionKey        = serviceSessionKey;
        svcPayload.keyVersion        = keyVersion_;
        svcPayload.type              = TicketType::SERVICE;
        svcPayload.authorityMetadata = "TGS_CLUSTER";

        auto encSvcKey = AES256CBC::encryptWithIV(serviceSessionKey, tgtPayload.sessionKey);

        auto signedBytes = TicketFactory::buildSignedBytes(svcPayload);
        auto encryptedTicket = TicketFactory::encryptPayload(svcPayload, serviceKey);

        AuthoritySignature authSig = MultiSchnorr::sign(signedBytes, nodeID_, share_.xi, params_);

        peer.send(Message::build("TGS_RESP", {
            std::to_string(nodeID_),
            std::to_string(keyVersion_),
            requestID,
            CryptoUtils::bytesToHex(encSvcKey),
            CryptoUtils::bytesToHex(encryptedTicket),
            CryptoUtils::bytesToBase64(signedBytes),
            signatureToHex(authSig),
        }));

        std::cout << "[TGS" << nodeID_ << "] TGS_RESP sent to " << clientID << "\n";
    }

    std::vector<uint8_t> loadServerKey(const std::string& filename) {
        std::string path = configDir_ + "/" + filename;
        std::ifstream f(path, std::ios::binary);
        if (f) {
            std::vector<uint8_t> key(32);
            f.read(reinterpret_cast<char*>(key.data()), 32);
            if (f.gcount() == 32) return key;
        }
        auto key = AES256CBC::randomKey();
        std::ofstream of(path, std::ios::binary);
        of.write(reinterpret_cast<const char*>(key.data()), 32);
        return key;
    }

    std::vector<uint8_t> deriveClusterSessionKey(const std::vector<uint8_t>& serverKey,
                                                 const std::string& requestID,
                                                 const std::string& clientID,
                                                 const std::string& serviceID,
                                                 int64_t authTimestamp) {
        std::string material = requestID + "|" + clientID + "|" + serviceID +
                               "|" + std::to_string(authTimestamp);
        std::vector<uint8_t> data = serverKey;
        data.insert(data.end(), material.begin(), material.end());
        auto d = SHA256::hash(data);
        return std::vector<uint8_t>(d.begin(), d.end());
    }
};

static TGSNode* g_tgsNode = nullptr;
static void sigHandler(int) { if (g_tgsNode) g_tgsNode->stop(); }

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: tgs_node <node_id> <port>\n";
        return 1;
    }
    int nodeID    = std::stoi(argv[1]);
    uint16_t port = (uint16_t)std::stoi(argv[2]);

    if (nodeID < 1 || nodeID > 3) {
        std::cerr << "node_id must be 1, 2, or 3\n";
        return 1;
    }

    if (!netInit()) { std::cerr << "Network init failed\n"; return 1; }

    TGSNode node(nodeID, port, "config");
    g_tgsNode = &node;

    std::signal(SIGINT,  sigHandler);
    std::signal(SIGTERM, sigHandler);

    if (!node.init()) return 1;
    node.run();

    netCleanup();
    return 0;
}
