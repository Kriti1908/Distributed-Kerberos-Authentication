#include "include/bigint.h"
#include "include/crypto_utils.h"
#include "include/schnorr.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <array>
#include <ctime>

namespace fs = std::filesystem;

class KeygenManager {
public:
    explicit KeygenManager(const std::string& configDir)
        : configDir_(configDir) {}

    void run(bool forceRegen) {
        fs::create_directories(configDir_);
        std::string paramsFile = configDir_ + "/params.txt";

        if (!forceRegen && fs::exists(paramsFile)) {
            std::cout << "[KeyGen] Config already exists. Use --regen to regenerate.\n";
            return;
        }

        std::cout << "[KeyGen] Generating Schnorr parameters (this may take a moment)...\n";
        SchnorrParams params = MultiSchnorr::generateParams();
        std::cout << "[KeyGen] Parameters generated.\n";
        std::cout << "  q bits: " << params.q.bits() << "\n";
        std::cout << "  p bits: " << params.p.bits() << "\n";

        params.save(paramsFile);
        std::cout << "[KeyGen] Saved: " << paramsFile << "\n";

        // ── Generate AS keys ──────────────────────────────────
        std::array<KeyShare, 3> asShares;
        for (int i = 0; i < 3; ++i) {
            asShares[i].index = i + 1;
            asShares[i].xi = MultiSchnorr::generatePrivateKey(params);
            
            std::string privName = configDir_ + "/as_share_" + std::to_string(i + 1) + ".txt";
            asShares[i].save(privName);
            std::cout << "[KeyGen] Saved: " << privName << "\n";

            BigInt pubKey = params.g.powMod(asShares[i].xi, params.p);
            std::string pubName = configDir_ + "/as_pubkey_" + std::to_string(i + 1) + ".txt";
            std::ofstream f(pubName);
            f << pubKey.toHex() << "\n";
        }

        // ── Generate TGS keys ─────────────────────────────────
        std::array<KeyShare, 3> tgsShares;
        for (int i = 0; i < 3; ++i) {
            tgsShares[i].index = i + 1;
            tgsShares[i].xi = MultiSchnorr::generatePrivateKey(params);
            
            std::string privName = configDir_ + "/tgs_share_" + std::to_string(i + 1) + ".txt";
            tgsShares[i].save(privName);
            std::cout << "[KeyGen] Saved: " << privName << "\n";

            BigInt pubKey = params.g.powMod(tgsShares[i].xi, params.p);
            std::string pubName = configDir_ + "/tgs_pubkey_" + std::to_string(i + 1) + ".txt";
            std::ofstream f(pubName);
            f << pubKey.toHex() << "\n";
        }

        // ── Read current key version ─────────────────────────────────────────
        int keyVersion = readKeyVersion();
        ++keyVersion;
        writeKeyVersion(keyVersion);
        std::cout << "[KeyGen] Key version: " << keyVersion << "\n";

        // ── Create default user registry ─────────────────────────────────────
        std::string usersFile = configDir_ + "/users.txt";
        if (!fs::exists(usersFile)) {
            writeDefaultUsers(usersFile);
            std::cout << "[KeyGen] Created default users: " << usersFile << "\n";
        }

        // ── Create default services ───────────────────────────────────────────
        std::string servicesFile = configDir_ + "/services.txt";
        if (!fs::exists(servicesFile)) {
            writeDefaultServices(servicesFile);
            std::cout << "[KeyGen] Created default services: " << servicesFile << "\n";
        }

        writeClusterServerKey(configDir_ + "/as_server_key.bin");
        writeClusterServerKey(configDir_ + "/tgs_server_key.bin");

        std::cout << "[KeyGen] Setup complete.\n";

        selfTest(params, asShares);
    }

private:
    std::string configDir_;

    int readKeyVersion() {
        std::string f = configDir_ + "/key_version.txt";
        if (!fs::exists(f)) return 0;
        std::ifstream ifs(f);
        int v = 1;
        ifs >> v;
        return v;
    }

    void writeKeyVersion(int v) {
        std::ofstream f(configDir_ + "/key_version.txt");
        f << v << "\n";
    }

    void writeDefaultUsers(const std::string& path) {
        std::ofstream f(path);
        struct { const char* user; const char* pass; } defaults[] = {
            {"alice",   "alice123"},
            {"bob",     "bob456"},
            {"charlie", "charlie789"},
            {"admin",   "admin_secret"},
        };
        for (auto& u : defaults) {
            auto h = SHA256::hash(std::string(u.pass));
            f << u.user << ":" << SHA256::hexdigest(h) << "\n";
        }
    }

    void writeDefaultServices(const std::string& path) {
        std::ofstream f(path);
        f << "fileserver\n";
        f << "printserver\n";
        f << "webservice\n";
        f << "database\n";
    }

    void writeClusterServerKey(const std::string& path) {
        auto key = AES256CBC::randomKey();
        std::ofstream f(path, std::ios::binary);
        if (!f) throw std::runtime_error("Cannot write " + path);
        f.write(reinterpret_cast<const char*>(key.data()), (std::streamsize)key.size());
        std::cout << "[KeyGen] Saved: " << path << "\n";
    }

    void selfTest(const SchnorrParams& params, const std::array<KeyShare, 3>& shares) {
        std::cout << "[KeyGen] Running self-test...\n";
        std::string msg = "test_ticket_payload";
        std::vector<uint8_t> msgBytes(msg.begin(), msg.end());

        // Generate independent signatures for nodes 1 and 2
        AuthoritySignature sig1 = MultiSchnorr::sign(msgBytes, shares[0].index, shares[0].xi, params);
        AuthoritySignature sig2 = MultiSchnorr::sign(msgBytes, shares[1].index, shares[1].xi, params);

        BigInt pk1 = params.g.powMod(shares[0].xi, params.p);
        BigInt pk2 = params.g.powMod(shares[1].xi, params.p);

        bool ok1 = MultiSchnorr::verify(sig1, msgBytes, pk1, params);
        bool ok2 = MultiSchnorr::verify(sig2, msgBytes, pk2, params);

        std::cout << "[KeyGen] Independent Schnorr self-test: " << (ok1 && ok2 ? "PASSED" : "FAILED") << "\n";

        if (!ok1 || !ok2) {
            std::cerr << "[KeyGen] CRITICAL: self-test failed! Keys may be corrupt.\n";
        }
    }
};

int main(int argc, char* argv[]) {
    bool forceRegen = false;
    for (int i = 1; i < argc; ++i)
        if (std::string(argv[i]) == "--regen") forceRegen = true;

    KeygenManager mgr("config");
    mgr.run(forceRegen);
    return 0;
}
