/**
 * @file      net_io.hpp
 * @brief     High-performance TCP network I/O channel for protocols.
 * * Design principles:
 * 1. Zero-Allocation Round-Trips: Reuses 'send_buffer' and 'recv_buffer' members 
 * to eliminate heap churn during massive data transfers (e.g., million-scale PSI).
 * 2. Headerless Protocol: No metadata (num/len) is sent. The pipe is a pure byte 
 * stream; alignment and framing are managed by the upper protocol logic.
 * 3. Unified API: Overloaded send() and receive() interfaces provide a clean 
 * abstraction while maintaining high performance.
 * 4. Hybrid Dispatch: Automatically chooses between buffer-linearization (memcpy) 
 * and zero-copy (writev) based on the data volume.
 */

#ifndef TAIHANG_NET_IO_HPP
#define TAIHANG_NET_IO_HPP

#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <cstddef>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/bigint.hpp>
#include <taihang/crypto/block.hpp>

namespace taihang::net {

// ---------------------------------------------------------------------------
// Tuning Constants
// ---------------------------------------------------------------------------

/** @brief Data size threshold to trigger writev() instead of memcpy. */
static constexpr size_t kMaxLinearizationSize = 1024 * 1024; // 1 MB
static constexpr size_t kDefaultBufferCapacity = 1024 * 1024;
static constexpr int kKernelSocketBufSize = 2 * 1024 * 1024;
static constexpr int kConnectMaxRetries = 20;
static constexpr int kConnectRetryDelayMs = 500;

class NetIO {
public:
    /**
     * @brief Opens a TCP connection.
     * @param party   "server" to listen/accept; "client" to connect.
     * @param address Target IPv4 address. Empty string binds to INADDR_ANY for server.
     * @param port    TCP port number.
     */
    NetIO(const std::string& party, const std::string& address, const uint16_t port);
    ~NetIO();

    // The socket is a unique resource; prevent accidental duplication.
    NetIO(const NetIO&) = delete;
    NetIO& operator=(const NetIO&) = delete;

    // ------------------------------------------------------------------
    // Buffered API: buffer()
    // These methods append data to 'send_buffer' without immediate syscalls.
    // ------------------------------------------------------------------

    void buffer(const void* data, size_t len);
    void buffer(const std::vector<ECPoint>& A);
    void buffer(const ZnElement& a);
    void buffer(const Block& b);
    void buffer(const std::vector<std::vector<uint8_t>>& M);
    void buffer(const std::vector<std::string>& S);

    /** @brief Sends all data in 'send_buffer' and resets its size. Memory is kept. */
    void flush();

    // ------------------------------------------------------------------
    // Immediate API: send()
    // Triggers network transmission immediately. Overloaded for all types.
    // ------------------------------------------------------------------

    void send(const void* data, size_t len);
    void send(const std::vector<ECPoint>& A);
    void send(const ZnElement& a);
    void send(const Block& b);
    void send(const std::vector<std::vector<uint8_t>>& M);
    void send(const std::vector<std::string>& S);

    // ------------------------------------------------------------------
    // Receive API: receive()
    // Blocks until the requested bytes are fully read from the kernel.
    // ------------------------------------------------------------------

    void recv(void* data, size_t len);
    void recv(std::vector<ECPoint>& A, size_t len);
    void recv(ZnElement& a);
    void recv(Block& b);
    void recv(std::vector<std::vector<uint8_t>>& A, size_t num, size_t len);
    void recv(std::vector<std::string>& S, size_t num, size_t len);

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------
    size_t pending_bytes() const { return send_buffer.size(); }
    int get_socket_fd() const { return connect_socket; }

private:
    // Internal socket management
    int setup_server(const std::string& address, uint16_t port);
    int setup_client(const std::string& address, uint16_t port);
    void configure_socket(int sock);

    // Primitive I/O wrappers
    void send_raw(const void* data, size_t len);
    void recv_raw(void* data, size_t len);
    void writev_all(std::vector<struct iovec>& iov);

    [[noreturn]] static void throw_errno(const char* context);

    bool is_server = false;
    int connect_socket = -1;
    int server_master_socket = -1;

    // Persistent buffers used to avoid repeated heap allocations.
    std::vector<uint8_t> send_buffer;
    std::vector<uint8_t> recv_buffer;
};

} // namespace taihang::net

#endif