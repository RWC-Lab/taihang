/****************************************************************************
 * @file      test_net_io.cpp
 * @brief     GTest suite for taihang::net::NetIO.
 *
 * Each test spins up a server thread and a client thread on localhost.
 * The server thread is launched first (it blocks on accept()), then the
 * client thread connects.  Both sides run their protocol logic, then join.
 *
 * Port allocation: each TEST_F fixture uses a unique base port so tests
 * can run in parallel without conflicts.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/net/net_io.hpp>
#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/bigint.hpp>
#include <taihang/crypto/block.hpp>
#include <taihang/crypto/zn.hpp>

#include <thread>
#include <atomic>
#include <functional>
#include <cstring>
#include <openssl/obj_mac.h>

using namespace taihang::net;
using namespace taihang;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

static const std::string kLocalhost = "127.0.0.1";

/**
 * @brief Runs server_fn and client_fn concurrently on the given port.
 *
 * The server thread is launched first.  The client thread starts 50 ms later
 * to give the server time to reach accept().  Both threads are joined before
 * the function returns, so any exception thrown inside propagates via
 * std::rethrow_exception after the join.
 */
void run_pair(uint16_t port,
              std::function<void(NetIO&)> server_fn,
              std::function<void(NetIO&)> client_fn) {
    std::exception_ptr server_ex, client_ex;

    std::thread server_thread([&]() {
        try {
            NetIO io("server", "", port);
            server_fn(io);
        } catch (...) {
            server_ex = std::current_exception();
        }
    });

    // Give the server a moment to reach accept().
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::thread client_thread([&]() {
        try {
            NetIO io("client", kLocalhost, port);
            client_fn(io);
        } catch (...) {
            client_ex = std::current_exception();
        }
    });

    server_thread.join();
    client_thread.join();

    if (server_ex) std::rethrow_exception(server_ex);
    if (client_ex) std::rethrow_exception(client_ex);
}

// ---------------------------------------------------------------------------
// Fixture — provides a shared ECGroup and a port counter
// ---------------------------------------------------------------------------

class NetIOTest : public ::testing::Test {
protected:
    void SetUp() override {
        group = std::make_shared<ECGroup>(NID_X9_62_prime256v1);
        field = std::make_shared<Zn>(group->order);
    }

    // Each test calls next_port() to get a fresh port.
    // Ports are allocated from a base to avoid cross-test conflicts.
    static uint16_t next_port() {
        static std::atomic<uint16_t> counter{19000};
        return counter++;
    }

    std::shared_ptr<ECGroup> group;
    std::shared_ptr<Zn>      field;
};

// ===========================================================================
// 1. Raw bytes  (send / buffer+flush / recv)
// ===========================================================================

TEST_F(NetIOTest, RawBytes_SendRecv_Small) {
    const uint16_t port = next_port();
    const std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0xFF, 0x00};

    run_pair(port,
        // server: send
        [&](NetIO& io) {
            io.send(payload.data(), payload.size());
        },
        // client: recv
        [&](NetIO& io) {
            std::vector<uint8_t> buf(payload.size());
            io.recv(buf.data(), buf.size());
            EXPECT_EQ(buf, payload);
        });
}

TEST_F(NetIOTest, RawBytes_BufferFlush_Small) {
    const uint16_t port = next_port();
    const std::vector<uint8_t> p1 = {0xAA, 0xBB};
    const std::vector<uint8_t> p2 = {0xCC, 0xDD, 0xEE};

    run_pair(port,
        [&](NetIO& io) {
            // Buffer two chunks, send in one Flush().
            io.buffer(p1.data(), p1.size());
            io.buffer(p2.data(), p2.size());
            EXPECT_EQ(io.pending_bytes(), p1.size() + p2.size());
            io.flush();
            EXPECT_EQ(io.pending_bytes(), 0UL);
        },
        [&](NetIO& io) {
            std::vector<uint8_t> buf(p1.size() + p2.size());
            io.recv(buf.data(), buf.size());
            EXPECT_EQ(std::vector<uint8_t>(buf.begin(), buf.begin() + p1.size()), p1);
            EXPECT_EQ(std::vector<uint8_t>(buf.begin() + p1.size(), buf.end()), p2);
        });
}

TEST_F(NetIOTest, RawBytes_Large_1MB) {
    const uint16_t port = next_port();
    const size_t N = 1024 * 1024;
    std::vector<uint8_t> payload(N);
    for (size_t i = 0; i < N; ++i) payload[i] = static_cast<uint8_t>(i & 0xFF);

    run_pair(port,
        [&](NetIO& io) { io.send(payload.data(), payload.size()); },
        [&](NetIO& io) {
            std::vector<uint8_t> buf(N);
            io.recv(buf.data(), N);
            EXPECT_EQ(buf, payload);
        });
}

TEST_F(NetIOTest, RawBytes_AllZeros) {
    const uint16_t port = next_port();
    const size_t N = 256;
    std::vector<uint8_t> payload(N, 0x00);

    run_pair(port,
        [&](NetIO& io) { io.send(payload.data(), N); },
        [&](NetIO& io) {
            std::vector<uint8_t> buf(N, 0xFF);
            io.recv(buf.data(), N);
            EXPECT_EQ(buf, payload);
        });
}

// ===========================================================================
// 2. Block
// ===========================================================================

TEST_F(NetIOTest, Block_SendRecv) {
    const uint16_t port = next_port();
    Block b;
    std::memset(&b, 0xAB, sizeof(Block));

    run_pair(port,
        [&](NetIO& io) { io.send(b); },
        [&](NetIO& io) {
            Block received;
            io.recv(received);
            EXPECT_EQ(std::memcmp(&b, &received, sizeof(Block)), 0);
        });
}

TEST_F(NetIOTest, Block_BufferFlush) {
    const uint16_t port = next_port();
    Block b1, b2;
    std::memset(&b1, 0x11, sizeof(Block));
    std::memset(&b2, 0x22, sizeof(Block));

    run_pair(port,
        [&](NetIO& io) {
            io.buffer(b1);
            io.buffer(b2);
            io.flush();
        },
        [&](NetIO& io) {
            Block r1, r2;
            io.recv(r1);
            io.recv(r2);
            EXPECT_EQ(std::memcmp(&b1, &r1, sizeof(Block)), 0);
            EXPECT_EQ(std::memcmp(&b2, &r2, sizeof(Block)), 0);
        });
}

// ===========================================================================
// 3. ECPoint
// ===========================================================================

TEST_F(NetIOTest, ECPoint_SendRecv_Single) {
    const uint16_t port = next_port();
    ECPoint pt = group->gen_random();

    run_pair(port,
        [&](NetIO& io) {
            std::vector<ECPoint> pts = {pt};
            io.send(pts);
        },
        [&](NetIO& io) {
            std::vector<ECPoint> received = {ECPoint(group)};
            io.recv(received, 1);
            EXPECT_EQ(received[0], pt);
        });
}

TEST_F(NetIOTest, ECPoint_SendRecv_Batch) {
    const uint16_t port = next_port();
    const size_t N = 100;
    std::vector<ECPoint> pts = group->gen_random(N);

    run_pair(port,
        [&](NetIO& io) { io.send(pts); },
        [&](NetIO& io) {
            std::vector<ECPoint> received(N, ECPoint(group));
            io.recv(received, N);
            for (size_t i = 0; i < N; ++i) {
                EXPECT_EQ(received[i], pts[i]) << "mismatch at i=" << i;
            }
        });
}

TEST_F(NetIOTest, ECPoint_BufferFlush_Batch) {
    const uint16_t port = next_port();
    const size_t N = 50;
    std::vector<ECPoint> pts = group->gen_random(N);

    run_pair(port,
        [&](NetIO& io) {
            io.buffer(pts);
            EXPECT_GT(io.pending_bytes(), 0UL);
            io.flush();
            EXPECT_EQ(io.pending_bytes(), 0UL);
        },
        [&](NetIO& io) {
            std::vector<ECPoint> received(N, ECPoint(group));
            io.recv(received, N);
            for (size_t i = 0; i < N; ++i) {
                EXPECT_EQ(received[i], pts[i]) << "mismatch at i=" << i;
            }
        });
}

TEST_F(NetIOTest, ECPoint_Generator_RoundTrip) {
    const uint16_t port = next_port();
    ECPoint g = group->get_generator();

    run_pair(port,
        [&](NetIO& io) {
            std::vector<ECPoint> pts = {g};
            io.send(pts);
        },
        [&](NetIO& io) {
            std::vector<ECPoint> received = {ECPoint(group)};
            io.recv(received, 1);
            EXPECT_EQ(received[0], g);
        });
}

TEST_F(NetIOTest, ECPoint_Infinity_RoundTrip) {
    const uint16_t port = next_port();
    ECPoint inf = group->get_infinity();

    run_pair(port,
        [&](NetIO& io) {
            std::vector<ECPoint> pts = {inf};
            io.send(pts);
        },
        [&](NetIO& io) {
            std::vector<ECPoint> received = {ECPoint(group)};
            io.recv(received, 1);
            EXPECT_TRUE(received[0].is_at_infinity());
        });
}

// ===========================================================================
// 4. ZnElement
// ===========================================================================

TEST_F(NetIOTest, ZnElement_SendRecv) {
    const uint16_t port = next_port();
    ZnElement a = field->gen_random();

    run_pair(port,
        [&](NetIO& io) { io.send(a); },
        [&](NetIO& io) {
            ZnElement received(field, BigInt(0ULL));
            io.recv(received);
            EXPECT_EQ(received.value, a.value);
        });
}

TEST_F(NetIOTest, ZnElement_BufferFlush) {
    const uint16_t port = next_port();
    ZnElement a1 = field->gen_random();
    ZnElement a2 = field->gen_random();

    run_pair(port,
        [&](NetIO& io) {
            io.buffer(a1);
            io.buffer(a2);
            io.flush();
        },
        [&](NetIO& io) {
            ZnElement r1(field, BigInt(0ULL));
            ZnElement r2(field, BigInt(0ULL));
            io.recv(r1);
            io.recv(r2);
            EXPECT_EQ(r1.value, a1.value);
            EXPECT_EQ(r2.value, a2.value);
        });
}

TEST_F(NetIOTest, ZnElement_Zero_RoundTrip) {
    const uint16_t port = next_port();
    ZnElement zero(field, BigInt(0ULL));

    run_pair(port,
        [&](NetIO& io) { io.send(zero); },
        [&](NetIO& io) {
            ZnElement r(field, BigInt(1ULL));
            io.recv(r);
            EXPECT_EQ(r.value, zero.value);
        });
}

// ===========================================================================
// 5. BytesMatrix  (std::vector<std::vector<uint8_t>>)
// ===========================================================================

TEST_F(NetIOTest, BytesMatrix_SendRecv_Small) {
    const uint16_t port = next_port();
    const size_t NUM = 4, LEN = 8;
    std::vector<std::vector<uint8_t>> M(NUM, std::vector<uint8_t>(LEN));
    for (size_t i = 0; i < NUM; ++i)
        for (size_t j = 0; j < LEN; ++j)
            M[i][j] = static_cast<uint8_t>(i * LEN + j);

    run_pair(port,
        [&](NetIO& io) { io.send(M); },
        [&](NetIO& io) {
            std::vector<std::vector<uint8_t>> R;
            io.recv(R, NUM, LEN);
            EXPECT_EQ(R, M);
        });
}

TEST_F(NetIOTest, BytesMatrix_SendRecv_LargeTriggersWritev) {
    const uint16_t port = next_port();
    // Total > kMaxLinearizationSize (1 MB) to trigger writev path.
    const size_t NUM = 1024, LEN = 1024 + 1;
    std::vector<std::vector<uint8_t>> M(NUM, std::vector<uint8_t>(LEN));
    for (size_t i = 0; i < NUM; ++i)
        for (size_t j = 0; j < LEN; ++j)
            M[i][j] = static_cast<uint8_t>((i + j) & 0xFF);

    run_pair(port,
        [&](NetIO& io) { io.send(M); },
        [&](NetIO& io) {
            std::vector<std::vector<uint8_t>> R;
            io.recv(R, NUM, LEN);
            EXPECT_EQ(R, M);
        });
}

TEST_F(NetIOTest, BytesMatrix_BufferFlush) {
    const uint16_t port = next_port();
    const size_t NUM = 3, LEN = 4;
    std::vector<std::vector<uint8_t>> M(NUM, std::vector<uint8_t>(LEN, 0xCC));

    run_pair(port,
        [&](NetIO& io) {
            io.buffer(M);
            io.flush();
        },
        [&](NetIO& io) {
            std::vector<std::vector<uint8_t>> R;
            io.recv(R, NUM, LEN);
            EXPECT_EQ(R, M);
        });
}

// ===========================================================================
// 6. StringVector  (std::vector<std::string>)
// ===========================================================================

TEST_F(NetIOTest, StringVector_SendRecv) {
    const uint16_t port = next_port();
    const size_t LEN = 16;
    std::vector<std::string> S = {"hello_world_1234", "taihang_net_test"};
    ASSERT_EQ(S[0].size(), LEN);
    ASSERT_EQ(S[1].size(), LEN);

    run_pair(port,
        [&](NetIO& io) { io.send(S); },
        [&](NetIO& io) {
            std::vector<std::string> R;
            io.recv(R, S.size(), LEN);
            EXPECT_EQ(R, S);
        });
}

TEST_F(NetIOTest, StringVector_BufferFlush) {
    const uint16_t port = next_port();
    const size_t LEN = 8;
    std::vector<std::string> S = {"aaaabbbb", "ccccdddd", "eeeeffff"};

    run_pair(port,
        [&](NetIO& io) {
            io.buffer(S);
            io.flush();
        },
        [&](NetIO& io) {
            std::vector<std::string> R;
            io.recv(R, S.size(), LEN);
            EXPECT_EQ(R, S);
        });
}

// ===========================================================================
// 7. Multi-round exchange (simulates a real MPC round structure)
// ===========================================================================

TEST_F(NetIOTest, MultiRound_PingPong_Bytes) {
    const uint16_t port = next_port();

    run_pair(port,
        [&](NetIO& io) {
            for (int round = 0; round < 5; ++round) {
                // Server sends round number.
                io.buffer(&round, sizeof(int));
                io.flush();
                // Server receives round number back.
                int echo;
                io.recv(&echo, sizeof(int));
                EXPECT_EQ(echo, round);
            }
        },
        [&](NetIO& io) {
            for (int round = 0; round < 5; ++round) {
                // Client receives and echoes back.
                int received;
                io.recv(&received, sizeof(int));
                EXPECT_EQ(received, round);
                io.send(&received, sizeof(int));
            }
        });
}

TEST_F(NetIOTest, MultiRound_MixedTypes) {
    const uint16_t port = next_port();

    ECPoint pt  = group->gen_random();
    ZnElement a = field->gen_random();
    Block b;
    std::memset(&b, 0x42, sizeof(Block));

    run_pair(port,
        // Server: buffer everything in one round, flush once
        [&](NetIO& io) {
            io.buffer(std::vector<ECPoint>{pt});
            io.buffer(a);
            io.buffer(b);
            io.flush();
        },
        // Client: recv each type separately
        [&](NetIO& io) {
            std::vector<ECPoint> rpt = {ECPoint(group)};
            ZnElement ra(field, BigInt(0ULL));
            Block rb;

            io.recv(rpt, 1);
            io.recv(ra);
            io.recv(rb);

            EXPECT_EQ(rpt[0], pt);
            EXPECT_EQ(ra.value, a.value);
            EXPECT_EQ(std::memcmp(&b, &rb, sizeof(Block)), 0);
        });
}

TEST_F(NetIOTest, MultiRound_BidirectionalExchange) {
    const uint16_t port = next_port();

    std::vector<ECPoint> server_pts = group->gen_random(10);
    std::vector<ECPoint> client_pts = group->gen_random(10);

    run_pair(port,
        [&](NetIO& io) {
            // Round 1: server sends its points
            io.send(server_pts);
            // Round 2: server receives client's points
            std::vector<ECPoint> received(10, ECPoint(group));
            io.recv(received, 10);
            for (size_t i = 0; i < 10; ++i) {
                EXPECT_EQ(received[i], client_pts[i]) << "server: mismatch at i=" << i;
            }
        },
        [&](NetIO& io) {
            // Round 1: client receives server's points
            std::vector<ECPoint> received(10, ECPoint(group));
            io.recv(received, 10);
            for (size_t i = 0; i < 10; ++i) {
                EXPECT_EQ(received[i], server_pts[i]) << "client: mismatch at i=" << i;
            }
            // Round 2: client sends its points
            io.send(client_pts);
        });
}

// ===========================================================================
// 8. Edge cases
// ===========================================================================

TEST_F(NetIOTest, EdgeCase_EmptyFlushIsNoop) {
    const uint16_t port = next_port();

    run_pair(port,
        [&](NetIO& io) {
            // Flushing with nothing buffered should not crash or send anything.
            io.flush();
            io.flush();
            // Then send a sentinel so the client can unblock.
            uint8_t sentinel = 0xFE;
            io.send(&sentinel, 1);
        },
        [&](NetIO& io) {
            uint8_t sentinel = 0x00;
            io.recv(&sentinel, 1);
            EXPECT_EQ(sentinel, 0xFE);
        });
}

TEST_F(NetIOTest, EdgeCase_PendingBytesTracksCorrectly) {
    const uint16_t port = next_port();

    run_pair(port,
        [&](NetIO& io) {
            EXPECT_EQ(io.pending_bytes(), 0UL);

            uint8_t a = 1, b = 2;
            io.buffer(&a, 1);
            EXPECT_EQ(io.pending_bytes(), 1UL);

            io.buffer(&b, 1);
            EXPECT_EQ(io.pending_bytes(), 2UL);

            io.flush();
            EXPECT_EQ(io.pending_bytes(), 0UL);
        },
        [&](NetIO& io) {
            uint8_t buf[2];
            io.recv(buf, 2);
            EXPECT_EQ(buf[0], 1);
            EXPECT_EQ(buf[1], 2);
        });
}

TEST_F(NetIOTest, EdgeCase_SingleByteRoundTrip) {
    const uint16_t port = next_port();

    run_pair(port,
        [](NetIO& io) {
            uint8_t v = 0x7F;
            io.send(&v, 1);
        },
        [](NetIO& io) {
            uint8_t v = 0x00;
            io.recv(&v, 1);
            EXPECT_EQ(v, 0x7F);
        });
}

TEST_F(NetIOTest, EdgeCase_MaxValueBytes) {
    const uint16_t port = next_port();
    // All-0xFF pattern: tests that no sign-extension or termination issues occur.
    const size_t N = 64;
    std::vector<uint8_t> payload(N, 0xFF);

    run_pair(port,
        [&](NetIO& io) { io.send(payload.data(), N); },
        [&](NetIO& io) {
            std::vector<uint8_t> buf(N, 0x00);
            io.recv(buf.data(), N);
            EXPECT_EQ(buf, payload);
        });
}