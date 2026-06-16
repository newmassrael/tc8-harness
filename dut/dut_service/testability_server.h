#pragma once

#include <netinet/in.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
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
    // SHUTDOWN — group-agnostic: socketId + typeId. typeId 0x00/0x01/0x02 map
    // to shutdown(fd, SHUT_RD/SHUT_WR/SHUT_RDWR) (PRS_TPSP §6.10).
    std::uint8_t shutdownSocket(const std::uint8_t *dat, std::size_t dat_len);
    // CONFIGURE_SOCKET — group-agnostic (PRS_TPSP §6.10.10): socketId + paramId +
    // paramVal(vint8). Maps each paramId to the matching setsockopt; the IP-level
    // options apply to both UDP and TCP, MSS/Nagle are TCP-only and the checksum
    // toggle UDP-only (an inapplicable option surfaces as the kernel EINVAL ->
    // E_NOK).
    std::uint8_t configureSocket(const std::uint8_t *dat, std::size_t dat_len);
    // RECEIVE_AND_FORWARD (PRS_TPSP §6.10) — socketId + maxFwd + maxLen, shared by
    // the UDP and TCP groups. Consumes the bytes queued before the call (returned
    // as dropCnt) to reopen the receive window, then spawns the matching forward
    // thread (receiveLoopUdp / receiveLoopTcp per `udp`); returns E_OK at once.
    std::uint8_t receiveAndForward(const std::uint8_t *dat, std::size_t dat_len,
                                   std::uint16_t service_id, const sockaddr_in &peer,
                                   std::vector<std::uint8_t> &resp_dat, bool udp);

    // Accept-thread body: poll `listen_fd` for up to `max_con` incoming
    // connections; per accept, register the new socket and emit the accept Event
    // to `peer`. Exits on stop_requested_ / reset_events_ / its own `stop` flag,
    // or after max_con accepts. `stop` is the per-worker flag the socket that
    // owns this thread raises when it is closed (stopWorker), so the thread can
    // never outlive its listen socket and race a reused fd.
    void acceptLoop(int listen_fd, std::uint16_t service_id, std::uint16_t listen_socket_id,
                    std::uint16_t max_con, sockaddr_in peer,
                    std::shared_ptr<std::atomic<bool>> stop);

    // TCP forward-thread body: consume up to `max_len` bytes from `conn_fd`,
    // emitting a forward Event (fullLen + payload, payload capped at `max_fwd`)
    // per recv() bulk to `peer`. Exits on stop/reset/its own `stop` flag, once
    // max_len bytes were consumed, or on peer close. `stop` is the per-worker
    // flag (see acceptLoop).
    void receiveLoopTcp(int conn_fd, std::uint16_t service_id, std::uint16_t max_fwd,
                        std::uint16_t max_len, sockaddr_in peer,
                        std::shared_ptr<std::atomic<bool>> stop);
    // UDP forward-thread body: per received datagram, emit a forward Event
    // (fullLen + srcPort + srcAddr + payload capped at `max_fwd`) to `peer` — the
    // connectionless variant carrying the datagram source (PRS_TPSP §6.10). A
    // zero-length datagram is a valid event, not an end-of-stream. Exits on the
    // same stop / reset / max_len conditions as the TCP body.
    void receiveLoopUdp(int sock_fd, std::uint16_t service_id, std::uint16_t max_fwd,
                        std::uint16_t max_len, sockaddr_in peer,
                        std::shared_ptr<std::atomic<bool>> stop);

    // Single emit path for every async Event (PRS_TPSP §6.2 TID 0x02, EVB-set
    // method id for group `gid`) — shared by the LISTEN_AND_ACCEPT (TCP) and
    // RECEIVE_AND_FORWARD (UDP/TCP) worker threads so the Event framing lives in
    // one place. See the .cpp for the fd_ concurrency invariant.
    void emitEvent(std::uint16_t service_id, std::uint8_t gid, std::uint8_t pid,
                   const std::vector<std::uint8_t> &dat, const sockaddr_in &peer);

    // Thread-safe socket-table access — the serverLoop thread and the accept
    // threads both touch the table, so all of socketId allocation, lookup, and
    // close go through these under sockets_mu_.
    std::uint16_t registerSocket(int fd);
    std::optional<int> lookupSocket(std::uint16_t id) const;
    bool eraseSocket(std::uint16_t id, bool abort = false);  // close (abort -> RST) + erase
    void closeAllSockets();

    // A connected TCP 4-tuple, captured at CONNECT for the abort SOCK_DESTROY.
    struct TcpConnTuple {
        sockaddr_in local{};
        sockaddr_in peer{};
    };
    // sock_diag SOCK_DESTROY (`ss -K`) for `t`'s 4-tuple — terminates a
    // TIME-WAIT residual that SO_LINGER + close leaves behind (the detached
    // tw_sock no longer maps to the fd). No-op for sockets already CLOSED.
    static void destroyTimeWaitResidual(const TcpConnTuple &t);

    // Signal the async-event SP threads to stop, join them, and clear the list.
    // Called by END_TEST (PRS_TPSP §6.10 "terminate active SPs") and by stop().
    void joinEventThreads();

    // Stop + join the async-event worker bound to `socket_id` (if any), then
    // erase it. Called by eraseSocket BEFORE ::close so the worker has exited and
    // no longer touches the fd when it is closed (and possibly reused) — the
    // invariant that keeps a worker thread's lifetime a strict subset of its
    // socket's. Acquires workers_mu_ only (never sockets_mu_), so it cannot
    // deadlock against a worker blocked in registerSocket().
    void stopWorker(std::uint16_t socket_id);

    int fd_ = -1;
    std::thread thread_;
    std::atomic<bool> stop_requested_{false};
    // Soft stop for the async-event SP threads on END_TEST, independent of the
    // hard stop_requested_ used for full shutdown.
    std::atomic<bool> reset_events_{false};

    // Async-event SP worker (LISTEN_AND_ACCEPT accept Events / RECEIVE_AND_FORWARD
    // forward Events) bound to the socket it serves: its `stop` flag plus the
    // thread. The worker's lifetime is owned by that socket — eraseSocket raises
    // `stop` and joins before ::close (stopWorker), and joinEventThreads reaps any
    // survivors at END_TEST / stop(). Keyed by socket_id so a close targets
    // exactly the worker on that socket; guarded by workers_mu_ (a finished worker
    // stays in the map until reaped, so the entry count is bounded by the
    // arm-per-case lifecycle, not by liveness).
    struct EventWorker {
        std::shared_ptr<std::atomic<bool>> stop;
        std::thread thread;
    };
    std::mutex workers_mu_;
    std::map<std::uint16_t, EventWorker> event_workers_;

    // PRS_TPSP §6.10 testability socket table: socketId -> fd, guarded by
    // sockets_mu_ (concurrent access from serverLoop + accept threads).
    mutable std::mutex sockets_mu_;
    std::map<std::uint16_t, int> sockets_;
    // Connected-TCP 4-tuples captured at CONNECT (active open only), keyed by
    // socketId — consulted by the abort path's SOCK_DESTROY. Passive-accepted
    // sockets are not tracked: no TIME-WAIT abort case exercises them, matching
    // the opcode firmware's active-only ss -K. Guarded by sockets_mu_; cleared
    // in lockstep with sockets_ (eraseSocket / closeAllSockets).
    std::map<std::uint16_t, TcpConnTuple> tcp_conn_;
    std::uint16_t next_socket_id_ = 1;
};

}  // namespace tc8::dut
