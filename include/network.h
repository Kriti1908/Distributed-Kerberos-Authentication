#pragma once
#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include <map>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socket_t = SOCKET;
  static constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <errno.h>
  #include <memory>
  using socket_t = int;
  static constexpr socket_t INVALID_SOCK = -1;
#endif

// ─────────────────────────────────────────────────────────────────────────────
//  Simple text-based message protocol
//  Wire format:  <4-byte big-endian length><message text>
//  Message text: TYPE|field1|field2|...\n  (pipe-delimited)
// ─────────────────────────────────────────────────────────────────────────────

struct Message {
    std::string type;
    std::vector<std::string> fields;

    std::string serialise() const;
    static Message deserialise(const std::string& s);
    static Message parse(const std::string& s) { return deserialise(s); }

    const std::string& get(size_t idx) const;
    static Message build(const std::string& type,
                         std::initializer_list<std::string> fields = {});
};

// ─────────────────────────────────────────────────────────────────────────────
//  NetworkPeer  –  wraps a socket with framed send/receive
// ─────────────────────────────────────────────────────────────────────────────
class NetworkPeer {
public:
    explicit NetworkPeer(socket_t sock);
    ~NetworkPeer();

    bool send(const Message& msg);
    bool send(const std::string& raw);
    bool recv(Message& msg, int timeoutMs = 5000);
    bool recv(std::string& raw, int timeoutMs = 5000);

    bool isConnected() const { return sock_ != INVALID_SOCK; }
    void close();

    socket_t raw() const { return sock_; }

private:
    bool sendRaw(const void* data, size_t len);
    bool recvAll (void* buf,  size_t len, int timeoutMs);

    socket_t sock_;
};

// ─────────────────────────────────────────────────────────────────────────────
//  TCPServer  –  single-threaded async-capable server
// ─────────────────────────────────────────────────────────────────────────────
class TCPServer {
public:
    using Handler = std::function<void(NetworkPeer& peer)>;

    TCPServer();
    ~TCPServer();

    bool bind(uint16_t port, const std::string& iface = "0.0.0.0");
    bool listen(int backlog = 10);
    // Accept one connection, call handler, then loop
    void run(const Handler& handler);
    // Accept one connection and return (for controlled tests)
    std::unique_ptr<NetworkPeer> acceptOne(int timeoutMs = -1);
    void stop();

private:
    socket_t     listenSock_;
    bool         running_;
};

// ─────────────────────────────────────────────────────────────────────────────
//  TCPClient  –  synchronous client connection
// ─────────────────────────────────────────────────────────────────────────────
class TCPClient {
public:
    TCPClient();
    ~TCPClient();

    bool connect(const std::string& host, uint16_t port, int timeoutMs = 3000);
    void disconnect();
    bool isConnected() const;

    bool send(const Message& msg);
    bool recv(Message& msg, int timeoutMs = 5000);

    // Convenience: send + wait for one response
    bool exchange(const Message& req, Message& resp, int timeoutMs = 5000);

private:
    socket_t sock_;
};

// ── Global WSA init (Windows only; no-op on Linux) ──────────────────────────
bool netInit();
void netCleanup();
