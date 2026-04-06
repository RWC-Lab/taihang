#include <taihang/net/net_io.hpp>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <cstring>
#include <iostream>
#include <thread>
#include <chrono>
#include <omp.h>
#include <openssl/bn.h>
#include <limits.h>

namespace taihang::net {

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

NetIO::NetIO(const std::string& party, const std::string& address, const uint16_t port)
    : is_server(party == "server") {
    
    // Dispatch setup based on role.
    connect_socket = is_server 
        ? setup_server(address, port) 
        : setup_client(address, port);

    configure_socket(connect_socket);

    // Warm up the buffers to reduce allocation latency during the first round.
    send_buffer.reserve(kDefaultBufferCapacity);
    recv_buffer.reserve(kDefaultBufferCapacity);
}

NetIO::~NetIO() {
    if (connect_socket >= 0) ::close(connect_socket);
    if (server_master_socket >= 0) ::close(server_master_socket);
}

// ---------------------------------------------------------------------------
// Buffered API Implementation
// ---------------------------------------------------------------------------

void NetIO::buffer(const void* data, size_t len) {
    if (len == 0) return;
    const auto* p = static_cast<const uint8_t*>(data);
    send_buffer.insert(send_buffer.end(), p, p + len);
}

void NetIO::buffer(const std::vector<ECPoint>& A) {
    if (A.size() == 0) return;
    size_t point_byte_len = A[0].group_ctx->point_byte_len;
    size_t offset = send_buffer.size();
    
    // Resize is preferred over insert here to avoid initializing new elements.
    send_buffer.resize(offset + A.size() * point_byte_len);
    uint8_t* dst = send_buffer.data() + offset;

    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < A.size(); ++i) {
        A[i].to_bytes(dst + i * point_byte_len);
    }
}

void NetIO::buffer(const ZnElement& a) {
    size_t offset = send_buffer.size();
    size_t element_byte_len = a.field_ctx->element_byte_len;
    send_buffer.resize(offset + element_byte_len);
    BN_bn2binpad(a.value.bn_ptr, send_buffer.data() + offset, element_byte_len);
}

void NetIO::buffer(const Block& b) {
    buffer(&b, sizeof(Block));
}

void NetIO::buffer(const std::vector<std::vector<uint8_t>>& M) {
    if (M.empty()) return;
    size_t len = M[0].size();
    size_t offset = send_buffer.size();
    send_buffer.resize(offset + M.size() * len);
    uint8_t* dst = send_buffer.data() + offset;

    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < M.size(); ++i) {
        std::memcpy(dst + i * len, M[i].data(), len);
    }
}

void NetIO::buffer(const std::vector<std::string>& S) {
    if (S.empty()) return;
    size_t len = S[0].size();
    size_t offset = send_buffer.size();
    send_buffer.resize(offset + S.size() * len);
    uint8_t* dst = send_buffer.data() + offset;

    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < S.size(); ++i) {
        std::memcpy(dst + i * len, S[i].data(), len);
    }
}

void NetIO::flush() {
    if (send_buffer.empty()) return;
    send_raw(send_buffer.data(), send_buffer.size());
    // Keeps the allocated memory (capacity) for subsequent rounds.
    send_buffer.clear(); 
}

// ---------------------------------------------------------------------------
// Immediate Send API Implementation
// ---------------------------------------------------------------------------

void NetIO::send(const void* data, size_t len) {
    send_raw(data, len);
}

void NetIO::send(const std::vector<ECPoint>& A) {
    buffer(A);
    flush();
}

void NetIO::send(const ZnElement& a) {
    buffer(a);
    flush();
}

void NetIO::send(const Block& b) {
    buffer(b);
    flush();
}

void NetIO::send(const std::vector<std::vector<uint8_t>>& M) {
    if (M.empty()) return;
    size_t total_size = M.size() * M[0].size();

    // Use scatter-gather writev() for zero-copy if the batch is large.
    if (total_size > kMaxLinearizationSize) {
        flush();
        std::vector<struct iovec> iov(M.size());
        for (size_t i = 0; i < M.size(); ++i) {
            iov[i].iov_base = const_cast<uint8_t*>(M[i].data());
            iov[i].iov_len  = M[i].size();
        }
        writev_all(iov);
    } else {
        buffer(M);
        flush();
    }
}

void NetIO::send(const std::vector<std::string>& S) {
    if (S.empty()) return;
    size_t total_size = S.size() * S[0].size();

    if (total_size > kMaxLinearizationSize) {
        flush();
        std::vector<struct iovec> iov(S.size());
        for (size_t i = 0; i < S.size(); ++i) {
            iov[i].iov_base = const_cast<char*>(S[i].data());
            iov[i].iov_len  = S[i].size();
        }
        writev_all(iov);
    } else {
        buffer(S);
        flush();
    }
}

// ---------------------------------------------------------------------------
// Receive API Implementation
// ---------------------------------------------------------------------------

void NetIO::recv(void* data, size_t len) {
    recv_raw(data, len);
}

// A must be properly initialized
void NetIO::recv(std::vector<ECPoint>& A, size_t len) {
    if (len == 0) return;
    size_t point_byte_len = A[0].group_ctx->point_byte_len;
    recv_buffer.resize(len * point_byte_len);
    recv_raw(recv_buffer.data(), recv_buffer.size());

    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < len; ++i) {
        A[i].from_bytes(recv_buffer.data() + i * point_byte_len);
    }
}

void NetIO::recv(ZnElement& a) {
    size_t element_byte_len = a.field_ctx->element_byte_len; 
    recv_buffer.resize(element_byte_len);
    recv_raw(recv_buffer.data(), element_byte_len);
    BN_bin2bn(recv_buffer.data(), element_byte_len, a.value.bn_ptr);
}

void NetIO::recv(Block& b) {
    recv_raw(&b, sizeof(Block));
}

void NetIO::recv(std::vector<std::vector<uint8_t>>& A, size_t num, size_t len) {
    recv_buffer.resize(num * len);
    recv_raw(recv_buffer.data(), recv_buffer.size());

    A.resize(num);
    for (size_t i = 0; i < num; ++i) {
        A[i].assign(recv_buffer.data() + i * len, recv_buffer.data() + (i + 1) * len);
    }
}

void NetIO::recv(std::vector<std::string>& S, size_t num, size_t len) {
    recv_buffer.resize(num * len);
    recv_raw(recv_buffer.data(), recv_buffer.size());

    S.resize(num);
    for (size_t i = 0; i < num; ++i) {
        S[i].assign(reinterpret_cast<char*>(recv_buffer.data() + i * len), len);
    }
}

// ---------------------------------------------------------------------------
// Internal Socket Setup & Low-level I/O
// ---------------------------------------------------------------------------

/**
 * @brief Initializes a TCP server, binds to a port, and blocks until a client connects.
 * @param address The IPv4 address to bind to. If empty, binds to INADDR_ANY (all interfaces).
 * @param port    The port number to listen on.
 * @return int    The connected socket file descriptor (ready for data transfer).
 * @note This implementation follows the standard Berkeley Sockets API. 
 */
int NetIO::setup_server(const std::string& address, uint16_t port) {
    // 1. Create the master "listening" socket.
    // AF_INET: IPv4 protocol family.
    // SOCK_STREAM: Connection-based, reliable byte stream (TCP).
    // IPPROTO_TCP: Explicitly specify TCP protocol.
    int master = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (master < 0) throw_errno("socket creation");
    
    // Store the master socket so it can be closed in the destructor.
    server_master_socket = master;

    // 2. Set Socket Options: SO_REUSEADDR.
    // This is CRITICAL for research/testing. It allows the server to bind to the 
    // same port immediately after a restart, bypassing the OS 'TIME_WAIT' state 
    // (typically 2 minutes) that occurs after a socket is closed.
    int reuse = 1;
    if (::setsockopt(master, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        throw_errno("setsockopt SO_REUSEADDR");
    }

    // 3. Prepare the server address structure.
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    // htons (Host-to-Network Short): Converts 16-bit port to Big-Endian (Network Byte Order).
    addr.sin_port   = htons(port); 
    
    if (address.empty()) {
        // Bind to all available network interfaces (0.0.0.0).
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        // Convert dotted-decimal IP string (e.g., "127.0.0.1") to binary format.
        addr.sin_addr.s_addr = ::inet_addr(address.c_str());
    }

    // 4. Bind the socket to the specified IP and Port.
    // This associates the socket with a specific network interface in the OS kernel.
    if (::bind(master, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        throw_errno("bind");
    }

    // 5. Start listening for incoming connections.
    // Backlog is set to 1 since MPC protocols usually involve a fixed pair of parties.
    // This puts the socket in a passive state, waiting for the client's SYN packet.
    if (::listen(master, 1) < 0) throw_errno("listen");

    std::cout << "[NetIO] Server listening on port " << port << "...\n";

    // 6. Block until a client connects (The TCP 3-way handshake).
    // accept() creates a NEW socket specifically for data transfer with this client,
    // leaving the 'master' socket free to (theoretically) listen for more connections.
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    
    // This call is BLOCKING. The thread will sleep here until a client calls connect().
    int conn = ::accept(master, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
    if (conn < 0) throw_errno("accept");

    // Log the successful connection with the client's IP.
    std::cout << "[NetIO] Client connected from " << ::inet_ntoa(client_addr.sin_addr) << "\n";
    
    return conn;
}

/**
 * @brief  Initializes the client-side TCP stack and attempts to establish a connection.
 * * This function implement a "Retry-on-Fail" strategy, which is standard in MPC 
 * frameworks to handle synchronization issues where the server and client are 
 * started simultaneously.
 *
 * @param  address  The IPv4 string of the target server (e.g., "192.168.1.10").
 * @param  port     The target TCP port.
 * @return int      An active file descriptor (FD) connected to the server.
 * @throws std::runtime_error If the connection cannot be established after max retries.
 */
int NetIO::setup_client(const std::string& address, uint16_t port) {
    // 1. CREATE THE CLIENT SOCKET
    // AF_INET: Specifies IPv4.
    // SOCK_STREAM: Specifies TCP (reliable byte stream).
    // IPPROTO_TCP: Explicitly sets the protocol to TCP.
    int sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        throw_errno("socket creation");
    }

    // 2. PREPARE THE TARGET ADDRESS STRUCTURE
    // We use sockaddr_in for IPv4 addressing.
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    
    // htons (Host-to-Network Short): Essential for cross-platform compatibility.
    // Converts the port number to Big-Endian (Network Byte Order) so the router 
    // and server kernel can interpret it correctly.
    addr.sin_port = htons(port);
    
    // ::inet_addr: Converts the "dotted-quad" IP string into a binary 32-bit 
    // network-order integer.
    addr.sin_addr.s_addr = ::inet_addr(address.c_str());

    // 3. THE CONNECT RETRY LOOP
    // In multi-party computation, parties often start at the "same" time.
    // If the client reaches this point before the server has called 'listen()', 
    // the 'connect()' call would immediately fail with ECONNREFUSED.
    for (int i = 0; i < kConnectMaxRetries; ++i) {
        // ::connect triggers the TCP 3-way handshake (SYN -> SYN-ACK -> ACK).
        // It is a BLOCKING call by default.
        if (::connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0) {
            // Success: Handshake completed.
            std::cout << "[NetIO] Connected to " << address << ":" << port << "\n";
            return sock;
        }

        // Log the failure and wait before retrying.
        // This prevents the client from "spamming" the network stack during startup.
        std::this_thread::sleep_for(std::chrono::milliseconds(kConnectRetryDelayMs));
    }

    // 4. CLEANUP ON FAILURE
    // If we reach this point, all retry attempts failed (likely a network issue 
    // or the server is down). We must close the FD to prevent a file descriptor leak.
    ::close(sock);
    
    throw std::runtime_error("[NetIO] Connection timed out after " + 
                             std::to_string(kConnectMaxRetries) + " retries at " + 
                             address + ":" + std::to_string(port));
}

/**
 * @brief  Optimizes the TCP stack for low-latency, high-throughput cryptographic tasks.
 * * This function fine-tunes the kernel-level behavior of the socket. Without these 
 * adjustments, the OS might apply generic "web-surfing" optimizations that severely 
 * degrade the performance of multi-round MPC protocols.
 *
 * @param  sock  The connected or listening socket file descriptor.
 */
void NetIO::configure_socket(int sock) {
    const int one = 1;

    // 1. DISABLE NAGLE'S ALGORITHM (TCP_NODELAY)
    // By default, TCP uses Nagle's algorithm to collect small outgoing packets and 
    // send them all at once to reduce header overhead.
    // * WHY IN MPC: MPC protocols (like OTs or Garbled Circuits) often involve many 
    // small "ping-pong" messages. Nagle's algorithm adds a ~40ms to 200ms delay 
    // waiting for the buffer to fill. 
    // Setting TCP_NODELAY=1 forces the kernel to send packets immediately.
    if (::setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
        throw_errno("setsockopt TCP_NODELAY");
    }

    // 2. TUNE KERNEL SEND BUFFER (SO_SNDBUF)
    // This sets the maximum size of the kernel-space buffer for outgoing data.
    // * SIGNIFICANCE: For high-bandwidth transfers (e.g., transferring million-scale 
    // PRF keys), the buffer must be large enough to hold data "in flight" 
    // (the Bandwidth-Delay Product). 
    // A 2MB buffer is typically a sweet spot for modern LAN/WAN research environments.
    if (::setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &kKernelSocketBufSize, sizeof(kKernelSocketBufSize)) < 0) {
        throw_errno("setsockopt SO_SNDBUF");
    }

    // 3. TUNE KERNEL RECEIVE BUFFER (SO_RCVBUF)
    // This sets the maximum size of the kernel-space buffer for incoming data.
    // * SIGNIFICANCE: If the sender is faster than the receiver's protocol logic, 
    // the kernel uses this buffer to "absorb" the burst. If this buffer fills up, 
    // the TCP window size drops to zero, forcing the sender to pause.
    // Increasing this ensures the network pipe stays full during heavy computation.
    if (::setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &kKernelSocketBufSize, sizeof(kKernelSocketBufSize)) < 0) {
        throw_errno("setsockopt SO_RCVBUF");
    }
}

void NetIO::send_raw(const void* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(connect_socket, static_cast<const char*>(data) + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) sent += n;
        else if (n == 0) throw std::runtime_error("NetIO: Peer closed connection.");
        else { if (errno == EINTR) continue; throw_errno("send"); }
    }
}

void NetIO::recv_raw(void* data, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t n = ::recv(connect_socket, static_cast<char*>(data) + received, len - received, 0);
        if (n > 0) received += n;
        else if (n == 0) throw std::runtime_error("NetIO: Peer closed connection.");
        else { if (errno == EINTR) continue; throw_errno("recv"); }
    }
}

void NetIO::writev_all(std::vector<struct iovec>& iov) {
    size_t iov_idx = 0;
    while (iov_idx < iov.size()) {
        int count = std::min<int>(IOV_MAX, static_cast<int>(iov.size() - iov_idx));
        ssize_t sent = ::writev(connect_socket, &iov[iov_idx], count);
        if (sent <= 0) { if (errno == EINTR) continue; throw_errno("writev"); }

        size_t remaining = static_cast<size_t>(sent);
        while (remaining > 0 && iov_idx < iov.size()) {
            if (remaining >= iov[iov_idx].iov_len) {
                remaining -= iov[iov_idx].iov_len;
                iov_idx++;
            } else {
                iov[iov_idx].iov_base = static_cast<char*>(iov[iov_idx].iov_base) + remaining;
                iov[iov_idx].iov_len -= remaining;
                remaining = 0;
            }
        }
    }
}

void NetIO::throw_errno(const char* context) {
    throw std::runtime_error(std::string("[NetIO Error] ") + context + ": " + std::strerror(errno));
}

} // namespace taihang::net