#include "include/bigint.h"
#include "include/crypto_utils.h"
#include "include/schnorr.h"
#include "include/ticket.h"
#include "include/network.h"

#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <set>
#include <mutex>
#include <atomic>
#include <csignal>
#include <ctime>

class ServiceServer {
public:
    ServiceServer(const std::string& serviceID, uint16_t port,
                  const std::string& configDir)
        : serviceID_(serviceID), port_(port), configDir_(configDir),
          running_(false), keyVersion_(1)
    {}

    bool init() {
        try {
            params_ = SchnorrParams::load(configDir_ + "/params.txt");
        } catch (const std::exception& e) {
            std::cerr << "[" << serviceID_ << "] Cannot load params: " << e.what() << "\n";
            return false;
        }

        for (int i = 1; i <= 3; ++i) {
            std::ifstream f(configDir_ + "/tgs_pubkey_" + std::to_string(i) + ".txt");
            if (f) {
                std::string hex;
                f >> hex;
                tgsPubKeys_[i] = BigInt(hex);
            } else {
                std::cerr << "[" << serviceID_ << "] Warning: Cannot load TGS pubkey " << i << "\n";
            }
        }

        loadKeyVersion();
        loadServerKey();

        if (!server_.bind(port_)) {
            std::cerr << "[" << serviceID_ << "] Cannot bind port " << port_ << "\n";
            return false;
        }
        server_.listen();

        std::cout << "[" << serviceID_ << "] Listening on port " << port_ << "\n";
        return true;
    }

    void run() {
        running_ = true;
        server_.run([this](NetworkPeer& peer) { handleClient(peer); });
        running_ = false;
    }

    void stop() { running_ = false; server_.stop(); }

private:
    std::string serviceID_;
    uint16_t    port_;
    std::string configDir_;
    std::atomic<bool> running_;

    SchnorrParams params_;
    std::map<int, BigInt> tgsPubKeys_;
    int           keyVersion_;
    std::vector<uint8_t> serverKey_;

    TCPServer server_;

    std::map<std::string, Session> sessions_;
    std::mutex sessionMtx_;

    std::set<std::string> usedAuthenticators_;
    std::mutex replayMtx_;

    void loadKeyVersion() {
        std::ifstream f(configDir_ + "/key_version.txt");
        if (f) f >> keyVersion_;
    }

    void loadServerKey() {
        std::string path = configDir_ + "/tgs_server_key.bin";
    
        std::ifstream f(path, std::ios::binary);
        if (f) {
            serverKey_.resize(32);
            f.read(reinterpret_cast<char*>(serverKey_.data()), 32);
            if ((size_t)f.gcount() == 32) return;
        }
    
        std::cout << "[" << serviceID_ << "] No server key found, generating new key...\n";    
        serverKey_ = AES256CBC::randomKey();
    
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(serverKey_.data()), 32);
    }

    void handleClient(NetworkPeer& peer) {
        Message req;
        if (!peer.recv(req)) return;

        if (req.type == "PING") {
            peer.send(Message::build("PONG", {serviceID_}));
        } else if (req.type == "SERVICE_REQ") {
            handleServiceReq(peer, req);
        } else if (req.type == "SERVICE_DATA") {
            handleServiceData(peer, req);
        } else {
            peer.send(Message::build("ERROR", {"Unknown: " + req.type}));
        }
    }

    void handleServiceReq(NetworkPeer& peer, const Message& req) {
        if (req.fields.size() < 3) {
            peer.send(Message::build("SVC_FAIL", {"Malformed request"}));
            return;
        }
        const std::string& clientID = req.fields[0];
        const std::string& tickB64  = req.fields[1];
        const std::string& authStr  = req.fields[2];

        std::cout << "[" << serviceID_ << "] SERVICE_REQ from " << clientID << "\n";

        Ticket ticket;
        try {
            ticket = Ticket::deserialise(tickB64);
        } catch (...) {
            peer.send(Message::build("SVC_FAIL", {"Bad ticket format"}));
            return;
        }

        if (ticket.keyVersion != keyVersion_) {
            peer.send(Message::build("SVC_FAIL",
                {"Outdated key version " + std::to_string(ticket.keyVersion) +
                 ", current=" + std::to_string(keyVersion_)}));
            return;
        }

        std::set<int> validAuthorities;
        for (const auto& sig : ticket.signatures) {
            if (validAuthorities.count(sig.authorityID)) continue;
            auto it = tgsPubKeys_.find(sig.authorityID);
            if (it == tgsPubKeys_.end()) continue;
            if (MultiSchnorr::verify(sig, ticket.signedBytes, it->second, params_))
                validAuthorities.insert(sig.authorityID);
        }

        if (validAuthorities.size() < 2) {
            std::cout << "[" << serviceID_
                      << "] INVALID ticket: only " << validAuthorities.size()
                      << " distinct valid signatures\n";
            peer.send(Message::build("SVC_FAIL", {"Not enough valid signatures"}));
            return;
        }

        TicketPayload payload;
        try {
            payload = TicketFactory::decryptPayload(ticket.encryptedPayload, serverKey_);
        } catch (const std::exception& e) {
            peer.send(Message::build("SVC_FAIL",
                {"Cannot decrypt ticket: " + std::string(e.what())}));
            return;
        }

        auto expectedSignedBytes = TicketFactory::buildSignedBytes(payload);
        if (expectedSignedBytes != ticket.signedBytes) {
            peer.send(Message::build("SVC_FAIL", {"Ticket payload/signature mismatch"}));
            return;
        }
        if (payload.keyVersion != ticket.keyVersion) {
            peer.send(Message::build("SVC_FAIL", {"Ticket key version mismatch"}));
            return;
        }
        if (payload.clientID != clientID) {
            peer.send(Message::build("SVC_FAIL", {"ClientID mismatch"}));
            return;
        }
        if (payload.serviceID != serviceID_) {
            peer.send(Message::build("SVC_FAIL",
                {"ServiceID mismatch: expected=" + serviceID_ +
                 " got=" + payload.serviceID}));
            return;
        }
        if (payload.isExpired()) {
            peer.send(Message::build("SVC_FAIL", {"Ticket expired"}));
            return;
        }
        if (payload.type != TicketType::SERVICE) {
            peer.send(Message::build("SVC_FAIL", {"Not a SERVICE ticket"}));
            return;
        }

        Authenticator auth;
        try {
            auth = Authenticator::deserialise(authStr);
        } catch (...) {
            peer.send(Message::build("SVC_FAIL", {"Bad authenticator format"}));
            return;
        }
        if (!TicketFactory::verifyAuthenticator(auth, payload.sessionKey)) {
            peer.send(Message::build("SVC_FAIL", {"Invalid authenticator"}));
            return;
        }

        {
            std::lock_guard<std::mutex> lk(replayMtx_);
            std::string authKey = clientID + "|" + std::to_string(auth.timestamp) + "|" +
                                  CryptoUtils::bytesToHex(auth.nonce);
            if (usedAuthenticators_.count(authKey)) {
                peer.send(Message::build("SVC_FAIL", {"Replay detected"}));
                return;
            }
            usedAuthenticators_.insert(authKey);
        }

        {
            std::lock_guard<std::mutex> lk(sessionMtx_);
            Session s;
            s.clientID   = clientID;
            s.serviceID  = serviceID_;
            s.sessionKey = payload.sessionKey;
            s.expiry     = payload.issueTimestamp + payload.lifetime;
            sessions_[clientID] = s;
        }

        std::cout << "[" << serviceID_ << "] Access GRANTED to " << clientID << "\n";
        peer.send(Message::build("SVC_OK", {
            serviceID_,
            clientID,
            "Access granted. Session established.",
        }));
    }

    void handleServiceData(NetworkPeer& peer, const Message& req) {
        if (req.fields.size() < 3) {
            peer.send(Message::build("SVC_FAIL", {"Malformed"}));
            return;
        }
        const std::string& clientID = req.fields[0];

        std::lock_guard<std::mutex> lk(sessionMtx_);
        auto it = sessions_.find(clientID);
        if (it == sessions_.end() || it->second.isExpired()) {
            peer.send(Message::build("SVC_FAIL", {"No valid session"}));
            return;
        }

        auto cipherData = CryptoUtils::base64ToBytes(req.fields[1]);
        std::vector<uint8_t> plain;
        try {
            plain = AES256CBC::decryptWithIV(cipherData, it->second.sessionKey);
        } catch (...) {
            peer.send(Message::build("SVC_FAIL", {"Decryption failed"}));
            return;
        }

        std::string request(plain.begin(), plain.end());
        std::cout << "[" << serviceID_ << "] Data from " << clientID
                  << ": " << request << "\n";

        std::string response = "RESPONSE:" + request;
        std::vector<uint8_t> respBytes(response.begin(), response.end());
        auto encResp = AES256CBC::encryptWithIV(respBytes, it->second.sessionKey);

        peer.send(Message::build("SVC_DATA_RESP", {
            CryptoUtils::bytesToBase64(encResp)
        }));
    }
};

static ServiceServer* g_server = nullptr;
static void sigHandler(int) { if (g_server) g_server->stop(); }

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: service_server <service_id> <port>\n";
        return 1;
    }
    std::string serviceID = argv[1];
    uint16_t    port      = (uint16_t)std::stoi(argv[2]);

    if (!netInit()) { std::cerr << "Network init failed\n"; return 1; }

    ServiceServer srv(serviceID, port, "config");
    g_server = &srv;

    std::signal(SIGINT,  sigHandler);
    std::signal(SIGTERM, sigHandler);

    if (!srv.init()) return 1;
    srv.run();

    netCleanup();
    return 0;
}
