#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <thread>
#include <vector>

#include "tc8/testability_protocol.h"

namespace tc8::dut {

// AUTOSAR Testability Protocol endpoint (PRS_TPSP §6, AUTOSAR TC 1.2.0),
// tc8-dut side — the standard-protocol counterpart to UpperTesterServer (the
// in-house opcode UT). Binds a UDP socket on the testability port and serves:
//
//   * GENERAL group (GID 0x00): GET_VERSION, START_TEST, END_TEST.
//   * UDP group (GID 0x01): CREATE_AND_BIND, SEND_DATA, CLOSE_SOCKET — a real
//     socket table, so a tester can drive the DUT to emit an observable UDP
//     datagram end to end.
//
// Wire framing + constants are the SSOT in include/tc8/testability_protocol.h,
// shared with the tester client so both ends decode identically. The endpoint
// is independent of the vsomeip/CommonAPI lifecycle (hand-rolled SOME/IP over
// a plain UDP socket per PRS_TPSP §5.1 "on top of UDP or TCP"). RAII: start() spawns the
// listener thread; stop()/dtor joins it and closes any open testability
// sockets.
class TestabilityServer {
public:
    TestabilityServer();
    ~TestabilityServer();

    TestabilityServer(const TestabilityServer &) = delete;
    TestabilityServer &operator=(const TestabilityServer &) = delete;

    // Bind the UDP listener and start the server thread. Returns false if the
    // bind fails (caller may keep running the opcode UT — testability is an
    // additive channel, not a hard precondition for opcode-speaking testers).
    bool start(std::uint16_t port = testability::kDefaultPort);

    // Signal the thread to exit, join it, and close any open sockets.
    // Idempotent.
    void stop();

private:
    void serverLoop();

    // Dispatch one parsed request. Writes the Result ID and any response DAT.
    void dispatch(const testability::Header &req, const std::uint8_t *dat,
                  std::size_t dat_len, std::uint8_t &rid_out,
                  std::vector<std::uint8_t> &resp_dat);

    // UDP group backends.
    std::uint8_t createAndBind(const std::uint8_t *dat, std::size_t dat_len,
                               std::uint16_t &socket_id_out);
    std::uint8_t sendData(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t closeSocket(const std::uint8_t *dat, std::size_t dat_len);

    void closeAllSockets();

    int fd_ = -1;
    std::thread thread_;
    std::atomic<bool> stop_requested_{false};

    // PRS_TPSP §6.10 testability socket table: socketId -> fd. Only the server thread
    // touches it (single listener, serial dispatch); stop() joins before
    // closing, so no lock is needed.
    std::map<std::uint16_t, int> sockets_;
    std::uint16_t next_socket_id_ = 1;
};

}  // namespace tc8::dut
