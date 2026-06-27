#include "include/network.h"
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <cerrno>
#include <memory>

#ifdef _WIN32
  #pragma comment(lib, "Ws2_32.lib")
#else
  #include <netdb.h>
  #include <fcntl.h>
  #include <unistd.h>
  #define closesocket close
#endif

// ─────────────────────────────────────────────────────────────────────────────
//  Platform init
// ─────────────────────────────────────────────────────────────────────────────
bool netInit() {
#ifdef _WIN32
    WSADATA wd;
    return WSAStartup(MAKEWORD(2,2), &wd) == 0;
#else
    return true;
#endif
}

void netCleanup() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
//  Message
// ─────────────────────────────────────────────────────────────────────────────
std::string Message::serialise() const {
    std::string s = type;
    for (const auto& f : fields) {
        s += "|";
        s += f;
    }
    return s + "\n";
}

Message Message::deserialise(const std::string& raw) {
    Message m;
    std::string s = raw;
    // strip trailing newline
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    std::istringstream ss(s);
    std::string token;
    bool first = true;
    while (std::getline(ss, token, '|')) {
        if (first) { m.type = token; first = false; }
        else        m.fields.push_back(token);
    }
    return m;
}

const std::string& Message::get(size_t idx) const {
    if (idx >= fields.size()) throw std::out_of_range("Message::get: index out of range");
    return fields[idx];
}

Message Message::build(const std::string& type,
                        std::initializer_list<std::string> fields) {
    Message m;
    m.type = type;
    m.fields = fields;
    return m;
}

// ─────────────────────────────────────────────────────────────────────────────
//  NetworkPeer
// ─────────────────────────────────────────────────────────────────────────────
NetworkPeer::NetworkPeer(socket_t sock) : sock_(sock) {}

NetworkPeer::~NetworkPeer() { close(); }

void NetworkPeer::close() {
    if (sock_ != INVALID_SOCK) {
#ifdef _WIN32
        ::closesocket(sock_);
#else
        ::close(sock_);
#endif
        sock_ = INVALID_SOCK;
    }
}

bool NetworkPeer::sendRaw(const void* data, size_t len) {
    const char* p = reinterpret_cast<const char*>(data);
    while (len > 0) {
        int sent = ::send(sock_, p, (int)len, 0);
        if (sent <= 0) return false;
        p   += sent;
        len -= sent;
    }
    return true;
}

bool NetworkPeer::recvAll(void* buf, size_t len, int timeoutMs) {
    if (timeoutMs >= 0) {
        struct timeval tv;
        tv.tv_sec  = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock_, &fds);
        int r = ::select((int)sock_ + 1, &fds, nullptr, nullptr, &tv);
        if (r <= 0) return false;
    }
    char* p = reinterpret_cast<char*>(buf);
    while (len > 0) {
        int got = ::recv(sock_, p, (int)len, 0);
        if (got <= 0) return false;
        p   += got;
        len -= got;
    }
    return true;
}

bool NetworkPeer::send(const Message& msg) {
    return send(msg.serialise());
}

bool NetworkPeer::send(const std::string& raw) {
    uint32_t len = (uint32_t)raw.size();
    // send length as big-endian 4 bytes then data
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24), (uint8_t)(len >> 16),
        (uint8_t)(len >>  8), (uint8_t)(len)
    };
    return sendRaw(hdr, 4) && sendRaw(raw.data(), raw.size());
}

bool NetworkPeer::recv(Message& msg, int timeoutMs) {
    std::string raw;
    if (!recv(raw, timeoutMs)) return false;
    msg = Message::deserialise(raw);
    return true;
}

bool NetworkPeer::recv(std::string& raw, int timeoutMs) {
    uint8_t hdr[4];
    if (!recvAll(hdr, 4, timeoutMs)) return false;
    uint32_t len = ((uint32_t)hdr[0]<<24)|((uint32_t)hdr[1]<<16)|
                   ((uint32_t)hdr[2]<<8 )|(uint32_t)hdr[3];
    if (len > 4 * 1024 * 1024) return false;  // sanity check 4MB
    raw.resize(len);
    if (len == 0) return true;
    return recvAll(&raw[0], len, timeoutMs);
}

// ─────────────────────────────────────────────────────────────────────────────
//  TCPServer
// ─────────────────────────────────────────────────────────────────────────────
TCPServer::TCPServer() : listenSock_(INVALID_SOCK), running_(false) {}

TCPServer::~TCPServer() {
    stop();
}

bool TCPServer::bind(uint16_t port, const std::string& iface) {
    listenSock_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock_ == INVALID_SOCK) return false;

    int opt = 1;
#ifdef _WIN32
    setsockopt(listenSock_, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    setsockopt(listenSock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, iface.c_str(), &addr.sin_addr);
    return ::bind(listenSock_,
                  reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
}

bool TCPServer::listen(int backlog) {
    return ::listen(listenSock_, backlog) == 0;
}

std::unique_ptr<NetworkPeer> TCPServer::acceptOne(int timeoutMs) {
    if (timeoutMs >= 0) {
        struct timeval tv;
        tv.tv_sec  = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(listenSock_, &fds);
        int r = ::select((int)listenSock_ + 1, &fds, nullptr, nullptr, &tv);
        if (r <= 0) return nullptr;
    }
    struct sockaddr_in clientAddr{};
    socklen_t addrLen = sizeof(clientAddr);
    socket_t client = ::accept(listenSock_,
                                reinterpret_cast<sockaddr*>(&clientAddr),
                                &addrLen);
    if (client == INVALID_SOCK) return nullptr;
    return std::make_unique<NetworkPeer>(client);
}

void TCPServer::run(const Handler& handler) {
    running_ = true;
    while (running_) {
        auto peer = acceptOne(500);
        if (!peer) continue;
        try { handler(*peer); }
        catch (const std::exception& e) {
            std::cerr << "[Server] Handler exception: " << e.what() << "\n";
        }
    }
}

void TCPServer::stop() {
    running_ = false;
    if (listenSock_ != INVALID_SOCK) {
        closesocket(listenSock_);
        listenSock_ = INVALID_SOCK;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  TCPClient
// ─────────────────────────────────────────────────────────────────────────────
TCPClient::TCPClient() : sock_(INVALID_SOCK) {}

TCPClient::~TCPClient() { disconnect(); }

bool TCPClient::connect(const std::string& host, uint16_t port, int timeoutMs) {
    sock_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ == INVALID_SOCK) return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    // Resolve hostname
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res) {
        addr.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    } else {
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    }

    // Set non-blocking for timeout
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock_, FIONBIO, &mode);
#else
    int flags = fcntl(sock_, F_GETFL, 0);
    fcntl(sock_, F_SETFL, flags | O_NONBLOCK);
#endif

    int cr = ::connect(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#ifdef _WIN32
    if (cr != 0) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            disconnect();
            return false;
        }
    }
#else
    if (cr != 0 && errno != EINPROGRESS) {
        disconnect();
        return false;
    }
#endif

    struct timeval tv;
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock_, &fds);
    int r = ::select((int)sock_ + 1, nullptr, &fds, nullptr, &tv);

    // Restore blocking
#ifdef _WIN32
    mode = 0;
    ioctlsocket(sock_, FIONBIO, &mode);
#else
    fcntl(sock_, F_SETFL, flags);
#endif

    if (r <= 0) { disconnect(); return false; }

    int soError = 0;
    socklen_t soLen = sizeof(soError);
#ifdef _WIN32
    if (getsockopt(sock_, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &soLen) != 0) {
        disconnect();
        return false;
    }
#else
    if (getsockopt(sock_, SOL_SOCKET, SO_ERROR, &soError, &soLen) != 0) {
        disconnect();
        return false;
    }
#endif
    if (soError != 0) {
        disconnect();
        return false;
    }
    return true;
}

void TCPClient::disconnect() {
    if (sock_ != INVALID_SOCK) {
        closesocket(sock_);
        sock_ = INVALID_SOCK;
    }
}

bool TCPClient::isConnected() const { return sock_ != INVALID_SOCK; }

bool TCPClient::send(const Message& msg) {
    if (sock_ == INVALID_SOCK) return false;
    std::string raw = msg.serialise();
    uint32_t len = (uint32_t)raw.size();
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24), (uint8_t)(len >> 16),
        (uint8_t)(len >> 8), (uint8_t)len
    };
    auto sendAll = [&](const void* d, size_t n) {
        const char* p = static_cast<const char*>(d);
        while (n > 0) {
            int s = ::send(sock_, p, (int)n, 0);
            if (s <= 0) return false;
            p += s;
            n -= s;
        }
        return true;
    };
    return sendAll(hdr, sizeof(hdr)) && sendAll(raw.data(), raw.size());
}

bool TCPClient::recv(Message& msg, int timeoutMs) {
    if (sock_ == INVALID_SOCK) return false;
    auto recvAll = [&](void* d, size_t n) {
        if (timeoutMs >= 0) {
            struct timeval tv;
            tv.tv_sec  = timeoutMs / 1000;
            tv.tv_usec = (timeoutMs % 1000) * 1000;
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(sock_, &fds);
            if (::select((int)sock_ + 1, &fds, nullptr, nullptr, &tv) <= 0) return false;
        }
        char* p = static_cast<char*>(d);
        while (n > 0) {
            int g = ::recv(sock_, p, (int)n, 0);
            if (g <= 0) return false;
            p += g;
            n -= g;
        }
        return true;
    };

    uint8_t rhdr[4];
    if (!recvAll(rhdr, 4)) return false;
    uint32_t rlen = ((uint32_t)rhdr[0] << 24) | ((uint32_t)rhdr[1] << 16) |
                    ((uint32_t)rhdr[2] << 8) | (uint32_t)rhdr[3];
    if (rlen > 4 * 1024 * 1024) return false;
    std::string rraw(rlen, '\0');
    if (rlen > 0 && !recvAll(&rraw[0], rlen)) return false;
    msg = Message::deserialise(rraw);
    return true;
}

bool TCPClient::exchange(const Message& req, Message& resp, int timeoutMs) {
    return send(req) && recv(resp, timeoutMs);
}
