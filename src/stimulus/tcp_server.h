#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "stimulus/endpoint.h"  // Endpoint — the peer ip:port (canonical SSOT, leaf header).

namespace tc8::stimulus {

// Tester-as-SERVER TCP accept surface for the server-role topology (TR_SOMEIP
// reliable transport). When the DUT acts as a SOME/IP client it OPENS the TCP
// connection to the tester's offered service endpoint, and the tester must
// accept it (the kernel completes the SYN/ACK handshake), track the
// per-connection peer, deliver SOME/IP Response/Notification bytes over it,
// observe a graceful FIN, or hold it open without answering (an application-layer
// blackhole). The kernel owns the TCP state machine — these are thin BSD-socket
// wrappers built on `openTcpListener`, NOT raw segment crafting. They pair with
// the server-role builders (buildMethodResponse / buildEventNotification /
// packSomeIpMessages) which produce the bytes sent over a connection.

// Open a TCP listener bound to `iface`'s IPv4 + `port`. SO_REUSEADDR is set so
// successive cases on the same port skip TIME_WAIT recycling. Returns the
// listening fd on success (caller closes), or a negative errno-derived sentinel
// on failure. This is the bind+listen SSOT the `TcpServer` ctor builds on; a
// case may also call it directly for the §5.1.6 SOMEIP_ETS_097 "refuse then
// accept" shape, where the absence of a listener makes the kernel emit RST on
// any SYN to the closed port (ECONNREFUSED on the DUT side, no active tester
// action) and constructing the listener partway through flips refuse -> accept.
//
// `non_blocking` sets O_NONBLOCK on the listener so accept() never blocks (it
// returns EAGAIN instead) — required when the listener is drained from a single
// non-blocking event loop (TcpAcceptService); failing to set it returns a
// sentinel rather than handing back a blocking fd. `backlog` is the listen()
// queue depth: 1 suits the synchronous one-accept cases; raise it when several
// DUT connections may be pending at once (autonomous multi-instance connects).
int openTcpListener(std::string_view iface, std::uint16_t port, bool non_blocking = false,
                    int backlog = 1);

// accept() with a poll-driven timeout. Returns 1 if an inbound connection was
// accepted (the accepted fd is immediately closed; ETS_097 only needs the
// wire-side handshake completion), 0 if the timeout elapsed without an accept,
// or a negative errno-derived sentinel on failure. The listener fd is left open
// so the caller can chain accept calls / close on its own timing.
int acceptTcpOnce(int listen_fd, std::chrono::milliseconds timeout);

// One accepted DUT->tester TCP connection. RAII: owns the accepted fd and closes
// it (sending the tester's FIN) on destruction. Move-only.
class TcpConnection {
  public:
    TcpConnection() = default;
    TcpConnection(int fd, const Endpoint &peer) : fd_(fd), peer_(peer) {}
    TcpConnection(TcpConnection &&o) noexcept;
    TcpConnection &operator=(TcpConnection &&o) noexcept;
    TcpConnection(const TcpConnection &) = delete;
    TcpConnection &operator=(const TcpConnection &) = delete;
    ~TcpConnection();

    bool valid() const { return fd_ >= 0; }
    int fd() const { return fd_; }
    // The DUT client's endpoint (source IP:port of its SYN), captured at accept —
    // the per-connection tracking the multi-connection cases need.
    const Endpoint &peer() const { return peer_; }

    // Deliver `bytes` (one SOME/IP message, or several packed via
    // packSomeIpMessages) to the DUT over this connection in one write call.
    // NOTE: TCP is a byte stream — the kernel, not this call, decides segment
    // boundaries, so a packed buffer is NOT guaranteed to land in a single
    // segment. That is fine: SOME/IP-over-TCP self-delimits via each message's
    // Length field, so the DUT reassembles regardless of segmentation. Returns 0
    // on success or a negative errno-derived sentinel.
    int send(const std::vector<std::uint8_t> &bytes);

    // Wait up to `timeout` for the peer's FIN — a graceful close from the DUT
    // side, observed as recv() == 0. Returns true if the FIN arrived within the
    // window, false on timeout. Any application bytes preceding the FIN are
    // drained and discarded; use recv() instead if the case needs them.
    bool waitForPeerFin(std::chrono::milliseconds timeout);

    // Poll up to `timeout` for inbound application bytes and append them to
    // `out`. Returns the count read (> 0), 0 on a peer FIN (EOF), or a negative
    // sentinel on error / timeout-with-nothing-read. Lets a case read a
    // DUT-sent Request over the reliable connection before answering.
    int recv(std::vector<std::uint8_t> &out, std::chrono::milliseconds timeout);

    // Explicit close (also run by the destructor). Idempotent.
    void close();

  private:
    int fd_ = -1;
    Endpoint peer_{};
};

// Tester TCP listener bound to `iface`'s IPv4 + `port`. RAII over the listening
// fd. Construct it at the moment the spec wants the port to start accepting: a
// DUT SYN arriving BEFORE construction hits a closed port and is RST by the
// kernel (the "RST a SYN, then accept the retry" shape = construct after the
// first SYN); constructing first makes the tester accept immediately. A
// transport-layer silent SYN-drop (neither SYN-ACK nor RST) is NOT expressible
// here — that needs a packet filter (e.g. iptables DROP) outside this surface;
// this class only does app-layer behaviours over an accepted connection.
// Move-only.
class TcpServer {
  public:
    // Opens the listener (SO_REUSEADDR, via openTcpListener). Pass `port` 0 to
    // bind a kernel-chosen ephemeral port and read it back via `port()`. On
    // failure valid() is false and the negative errno is logged; check valid()
    // before accept. `non_blocking`/`backlog` forward to openTcpListener (see
    // there): the synchronous accept cases keep the blocking, backlog-1 defaults;
    // TcpAcceptService passes a non-blocking listener with a deeper backlog.
    TcpServer(std::string_view iface, std::uint16_t port, bool non_blocking = false,
              int backlog = 1);
    TcpServer(TcpServer &&o) noexcept;
    TcpServer &operator=(TcpServer &&o) noexcept;
    TcpServer(const TcpServer &) = delete;
    TcpServer &operator=(const TcpServer &) = delete;
    ~TcpServer();

    bool valid() const { return listen_fd_ >= 0; }
    int fd() const { return listen_fd_; }  // for folding into a capture poll loop.
    // The actual bound port (host order), resolved via getsockname — meaningful
    // when constructed with port 0. Returns 0 if the listener is invalid.
    std::uint16_t port() const;

    // Poll up to `timeout` for an inbound DUT connection and accept it, capturing
    // the peer's source IP:port into the returned connection. Returns the
    // connection on success, or std::nullopt on timeout / error. Call repeatedly
    // for the multi-connection cases (two service instances).
    std::optional<TcpConnection> acceptOne(std::chrono::milliseconds timeout);

  private:
    void closeListener();
    int listen_fd_ = -1;
};

}  // namespace tc8::stimulus
