#pragma once

#include <netinet/in.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
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
//   * TCP group (GID 0x02): CREATE_AND_BIND, CONNECT, SEND_DATA, CLOSE_SOCKET
//     (active-open lifecycle) plus LISTEN_AND_ACCEPT (passive open). The latter
//     marks a bound socket as listening, returns E_OK immediately, and then —
//     per accepted connection — emits an asynchronous Event (PRS_TPSP §6.2 TID
//     0x02) to the requesting tester carrying the new socket id and the client
//     port/address, so the DUT can be driven into ESTABLISHED as a server.
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
    // `peer` is the requester address — LISTEN_AND_ACCEPT remembers it as the
    // destination for the asynchronous accept Event.
    void dispatch(const testability::Header &req, const std::uint8_t *dat,
                  std::size_t dat_len, const sockaddr_in &peer, std::uint8_t &rid_out,
                  std::vector<std::uint8_t> &resp_dat);

    // UDP/TCP CREATE_AND_BIND (PRS_TPSP §6.10) — the request shape is identical
    // across both groups; `socktype` selects SOCK_DGRAM (UDP) / SOCK_STREAM (TCP).
    std::uint8_t createAndBind(const std::uint8_t *dat, std::size_t dat_len, int socktype,
                               std::uint16_t &socket_id_out);
    // Dispatch helper shared by the UDP/TCP arms: bind, and on success append the
    // new socketId to the response (the create reply shape is group-independent).
    void respondCreateAndBind(int socktype, const std::uint8_t *dat, std::size_t dat_len,
                              std::uint8_t &rid_out, std::vector<std::uint8_t> &resp_dat);
    // UDP SEND_DATA — connectionless: socketId + totalLen + destPort + destAddr + data.
    std::uint8_t sendDataUdp(const std::uint8_t *dat, std::size_t dat_len);
    // TCP SEND_DATA — connection-oriented: socketId + totalLen + flags + data.
    std::uint8_t sendDataTcp(const std::uint8_t *dat, std::size_t dat_len);
    // TCP CONNECT (active open) — socketId + destPort + destAddr.
    std::uint8_t connectTcp(const std::uint8_t *dat, std::size_t dat_len);
    // TCP LISTEN_AND_ACCEPT (passive open) — listenSocketId + maxCon. Marks the
    // socket as listening and spawns an accept thread emitting Events to `peer`.
    std::uint8_t listenAndAcceptTcp(const std::uint8_t *dat, std::size_t dat_len,
                                    std::uint16_t service_id, const sockaddr_in &peer);
    // CLOSE_SOCKET — group-agnostic (an fd is an fd): socketId.
    std::uint8_t closeSocket(const std::uint8_t *dat, std::size_t dat_len);

    // Accept-thread body: poll `listen_fd` for up to `max_con` incoming
    // connections; per accept, register the new socket and emit the accept Event
    // to `peer`. Exits on stop_requested_ or after max_con accepts.
    void acceptLoop(int listen_fd, std::uint16_t service_id, std::uint16_t listen_socket_id,
                    std::uint16_t max_con, sockaddr_in peer);

    // Thread-safe socket-table access — the serverLoop thread and the accept
    // threads both touch the table, so all of socketId allocation, lookup, and
    // close go through these under sockets_mu_.
    std::uint16_t registerSocket(int fd);
    std::optional<int> lookupSocket(std::uint16_t id) const;
    bool eraseSocket(std::uint16_t id);  // close + erase; false if absent
    void closeAllSockets();

    // Signal the accept threads to stop, join them, and clear the list. Called
    // by END_TEST (PRS_TPSP §6.10 "terminate active SPs") and by stop().
    void joinAcceptThreads();

    int fd_ = -1;
    std::thread thread_;
    std::atomic<bool> stop_requested_{false};
    // Soft stop for accept threads on END_TEST, independent of the hard
    // stop_requested_ used for full shutdown.
    std::atomic<bool> reset_accepts_{false};

    // Accept threads spawned by LISTEN_AND_ACCEPT; joined before the socket
    // table is torn down (END_TEST resets them, stop() shuts them down).
    std::vector<std::thread> accept_threads_;

    // PRS_TPSP §6.10 testability socket table: socketId -> fd, guarded by
    // sockets_mu_ (concurrent access from serverLoop + accept threads).
    mutable std::mutex sockets_mu_;
    std::map<std::uint16_t, int> sockets_;
    std::uint16_t next_socket_id_ = 1;
};

}  // namespace tc8::dut
