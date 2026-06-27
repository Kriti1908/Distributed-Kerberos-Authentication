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
#include <mutex>
#include <thread>
#include <filesystem>
#include <atomic>
#include <csignal>
#include <ctime>

namespace fs = std::filesystem;

class AuthorityNode {
public:
    AuthorityNode(int nodeID, uint16_t port, const std::string& configDir)
        : nodeID_(nodeID), port_(port), configDir_(configDir),
          running_(false), keyVersion_(1)
    {}

    bool init() {
        try {
            params_ = SchnorrParams::load(configDir_ + "/params.txt");
        } catch (const std::exception& e) {
            std::cerr << "[AS" << nodeID_ << "] Failed to load params: " << e.what() << "\n";
            return false;
        }

        std::string shareFile = configDir_ + "/as_share_" + std::to_string(nodeID_) + ".txt";
        try {
            share_ = KeyShare::load(shareFile);
        } catch (const std::exception& e) {
            std::cerr << "[AS" << nodeID_ << "] Failed to load share: " << e.what() << "\n";
            return false;
        }

        loadUsers();
        loadKeyVersion();

        if (!server_.bind(port_)) {
            std::cerr << "[AS" << nodeID_ << "] Failed to bind port " << port_ << "\n";
            return false;
        }
        if (!server_.listen()) {
            std::cerr << "[AS" << nodeID_ << "] Failed to listen\n";
            return false;
        }

        std::cout << "[AS" << nodeID_ << "] Listening on port " << port_ << "\n";
        std::cout << "[AS" << nodeID_ << "] keyVersion=" << keyVersion_ << "\n";
        return true;
    }

    void run() {
        running_ = true;
        std::thread rotTimer([this]() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::seconds(KEY_ROTATION_INTERVAL));
                rotateKeys();
            }
        });

        server_.run([this](NetworkPeer& peer) {
            handleClient(peer);
        });

        running_ = false;
        if (rotTimer.joinable()) rotTimer.detach();
    }

    void stop() { running_ = false; server_.stop(); }

private:
    int        nodeID_;
    uint16_t   port_;
    std::string configDir_;
    std::atomic<bool> running_;

    SchnorrParams params_;
    KeyShare      share_;
    int           keyVersion_;

    std::map<std::string, std::string> users_;

    TCPServer     server_;

    static constexpr int KEY_ROTATION_INTERVAL = 3600;

    void loadUsers() {
        std::ifstream f(configDir_ + "/users.txt");
        std::string line;
        while (std::getline(f, line)) {
            auto p = line.find(':');
            if (p == std::string::npos) continue;
            users_[line.substr(0, p)] = line.substr(p + 1);
        }
        std::cout << "[AS" << nodeID_ << "] Loaded " << users_.size() << " users.\n";
    }

    bool verifyCredentials(const std::string& username, const std::string& password) {
        auto it = users_.find(username);
        if (it == users_.end()) return false;
        auto h = SHA256::hash(password);
        return SHA256::hexdigest(h) == it->second;
    }

    void loadKeyVersion() {
        std::ifstream f(configDir_ + "/key_version.txt");
        if (f) f >> keyVersion_;
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
                                                 int64_t issueTimestamp) {
        std::string material = requestID + "|" + clientID + "|" + serviceID +
                               "|" + std::to_string(issueTimestamp);
        std::vector<uint8_t> data = serverKey;
        data.insert(data.end(), material.begin(), material.end());
        auto d = SHA256::hash(data);
        return std::vector<uint8_t>(d.begin(), d.end());
    }

    void rotateKeys() {
        std::cout << "[AS" << nodeID_ << "] Rotating keys...\n";
        try {
            params_ = SchnorrParams::load(configDir_ + "/params.txt");
            share_  = KeyShare::load(configDir_ + "/as_share_" + std::to_string(nodeID_) + ".txt");
            loadKeyVersion();
            std::cout << "[AS" << nodeID_ << "] Keys reloaded. Version: " << keyVersion_ << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[AS" << nodeID_ << "] Key rotation failed: " << e.what() << "\n";
        }
    }

    void handleClient(NetworkPeer& peer) {
        Message req;
        if (!peer.recv(req)) return;

        if (req.type == "PING") {
            peer.send(Message::build("PONG", {std::to_string(nodeID_)}));
            return;
        }

        if (req.type == "AUTH_REQ") {
            handleAuthReq(peer, req);
        } else {
            peer.send(Message::build("ERROR", {"Unknown message type: " + req.type}));
        }
    }

    void handleAuthReq(NetworkPeer& peer, const Message& req) {
        if (req.fields.size() < 5) {
            peer.send(Message::build("AUTH_FAIL", {"Malformed request"}));
            return;
        }
        const std::string& clientID  = req.fields[0];
        const std::string& password  = req.fields[1];
        const std::string& requestID = req.fields[2];
        const std::string& serviceID = req.fields[3];
        int64_t issueTimestamp = 0;
        try {
            issueTimestamp = std::stoll(req.fields[4]);
        } catch (...) {
            peer.send(Message::build("AUTH_FAIL", {"Bad timestamp"}));
            return;
        }

        std::cout << "[AS" << nodeID_ << "] AUTH_REQ from " << clientID << "\n";

        if (!verifyCredentials(clientID, password)) {
            std::cout << "[AS" << nodeID_ << "] Auth FAILED for " << clientID << "\n";
            peer.send(Message::build("AUTH_FAIL", {"Invalid credentials"}));
            return;
        }

        auto serverKey = loadServerKey("as_server_key.bin");
        auto sessionKey = deriveClusterSessionKey(serverKey, requestID, clientID, serviceID, issueTimestamp);

        TicketPayload payload;
        payload.clientID          = clientID;
        payload.serviceID         = (serviceID.empty() ? "krbtgt" : serviceID);
        payload.issueTimestamp    = issueTimestamp;
        payload.lifetime          = TicketFactory::TGT_LIFETIME;
        payload.sessionKey        = sessionKey;
        payload.keyVersion        = keyVersion_;
        payload.type              = TicketType::TGT;
        payload.authorityMetadata = "AS_CLUSTER";
        
        auto encryptedTicket = TicketFactory::encryptPayload(payload, serverKey);

        auto salt = CryptoUtils::randomBytes(16);
        auto clientKey = CryptoUtils::deriveKey(password, salt, 1000);
        auto encSessionKey = AES256CBC::encryptWithIV(sessionKey, clientKey);

        auto signedBytes = TicketFactory::buildSignedBytes(payload);
        
        AuthoritySignature authSig = MultiSchnorr::sign(signedBytes, nodeID_, share_.xi, params_);

        peer.send(Message::build("AUTH_RESP", {
            std::to_string(nodeID_),
            std::to_string(keyVersion_),
            requestID,
            CryptoUtils::bytesToHex(encSessionKey),
            CryptoUtils::bytesToHex(salt),
            CryptoUtils::bytesToHex(encryptedTicket),
            CryptoUtils::bytesToBase64(signedBytes),
            signatureToHex(authSig)
        }));

        std::cout << "[AS" << nodeID_ << "] Sent AUTH_RESP to " << clientID << "\n";
    }
};

static AuthorityNode* g_asNode = nullptr;

static void sigHandler(int) {
    if (g_asNode) g_asNode->stop();
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: as_node <node_id> <port>\n";
        return 1;
    }

    int nodeID = std::stoi(argv[1]);
    uint16_t port = (uint16_t)std::stoi(argv[2]);

    if (nodeID < 1 || nodeID > 3) {
        std::cerr << "node_id must be 1, 2, or 3\n";
        return 1;
    }

    if (!netInit()) {
        std::cerr << "Network init failed\n";
        return 1;
    }

    AuthorityNode node(nodeID, port, "config");
    g_asNode = &node;

    std::signal(SIGINT,  sigHandler);
    std::signal(SIGTERM, sigHandler);

    if (!node.init()) return 1;
    node.run();

    netCleanup();
    return 0;
}
