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
    // before accept.
    TcpServer(std::string_view iface, std::uint16_t port);
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
