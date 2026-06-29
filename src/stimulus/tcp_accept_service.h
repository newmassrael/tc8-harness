#pragma once

#include <cstdint>
#include <functional>
#include <string_view>

#include "stimulus/tcp_server.h"     // TcpServer / TcpConnection — the wrapped primitive.
#include "tc8/pollable_service.h"    // IPollableService — the capture-loop drain seam.

namespace tc8::stimulus {

// Handler invoked on the capture-loop thread once per DUT->tester TCP connection
// the service accepts. Ownership of the accepted connection MOVES into the
// handler. Because it runs on the SINGLE capture thread, the handler MUST NOT
// block: do only non-blocking work — push a bounded reply that fits the socket
// send buffer (one SOME/IP Response/Notification via TcpConnection::send), or
// MOVE the connection into longer-lived storage for the case to service later.
// It must NOT call the blocking TcpConnection::recv / waitForPeerFin inline:
// those wait up to their timeout and would stall capture and every other adopted
// service. Request/Response interaction over a held connection belongs to the
// synchronous TcpServer::acceptOne path (or a future per-connection pollable
// seam), not here.
//
// LIFETIME NOTE: a connection the handler does not retain destructs when the
// handler returns — close() sends a graceful FIN when no unread inbound bytes
// remain, otherwise an RST. To realise the app-layer BLACKHOLE shape (accept
// then hold open silently), the handler MOVEs the connection into storage it
// owns rather than letting it fall off the end of the callback. The reply
// CONTENT lives entirely in the handler, so this service carries no OEM/NDA
// payload — the same "policy in the caller's callback" split as
// MethodResponder's reply builder.
using TcpAcceptHandler = std::function<void(TcpConnection)>;

// Tester-as-SERVER autonomous TCP-accept service: a run-scoped IPollableService
// that accepts DUT-initiated TCP connections arriving at ANY point in the
// capture window, for the case where the DUT (in its SOME/IP client role) opens
// the reliable connection on ITS OWN schedule rather than synchronously in
// direct response to a just-emitted Offer.
//
// When to use which surface:
//   - SYNCHRONOUS connect (DUT connects right after a tester stimulus, ETS_097):
//     call TcpServer::acceptOne(timeout) inline in stimulus() — a bounded block
//     is correct because the connect is expected within the window.
//   - AUTONOMOUS connect (timing unknown, anywhere in the window): the accept
//     cannot block the single capture thread, so it must fold into the drain
//     loop. THIS adapter is that fold: its pollFd() is the listener, and
//     onReadable() does a non-blocking accept each capture-loop iteration.
//
// Lifetime + threading model are identical to MethodResponder / ArpResponder
// (see tc8/pollable_service.h): a case builds it in stimulus() and hands it to
// the runner via IBackgroundServiceOwner::adoptService so it outlives stimulus()
// and lives across the capture window; the CLI capture loop folds pollFd() into
// its drain set and calls onReadable() each iteration on the SAME thread as
// frame dispatch — no worker thread, no capture/emit concurrency. The listener
// is non-blocking (intrinsically, via openTcpListener) so onReadable()'s accept
// never stalls that thread, even if a SYN is withdrawn (RST) between the poll
// and the accept.
//
// Unlike MethodResponder/ArpResponder this needs NO raw-packet capability: the
// kernel runs the TCP handshake on a bound listening socket (the same
// unprivileged listen() that TcpServer / openTcpListener perform), so a stimulus
// need only bind the tester's offered service endpoint.
//
// CONSUMER STATUS: this is the public, NDA-clean accept seam for autonomous
// SOMEIPCLT cases; the production driver (a DUT-in-client-role case) is
// out-of-tree. No in-tree case adopts it yet — its in-tree contract is the
// hermetic loopback unit test (unit_tests/tcp_accept_service_test.cpp). Land an
// in-tree consumer alongside the first case that needs it.
//
// Non-copyable: owns a live listening socket (through TcpServer).
class TcpAcceptService : public ::tc8::IPollableService {
  public:
    // Binds a listener on `iface`'s IPv4 + `port` (port 0 -> a kernel-chosen
    // ephemeral port, read back via boundPort()). `handler` runs on the capture
    // thread for each accepted connection. Check ok() before adopting the
    // service; a !ok() service reports pollFd() == -1 and the capture loop skips
    // it.
    TcpAcceptService(std::string_view iface, std::uint16_t port, TcpAcceptHandler handler);
    ~TcpAcceptService() override = default;  // TcpServer RAII closes the listener.

    TcpAcceptService(const TcpAcceptService &) = delete;
    TcpAcceptService &operator=(const TcpAcceptService &) = delete;

    // False if the listener could not be bound (e.g. the interface has no IPv4
    // address). The case should surface this (inconclusive) rather than assume
    // the DUT's connect will be accepted.
    bool ok() const { return server_.valid(); }

    // The actual bound port (host order) — meaningful when constructed with port
    // 0. Returns 0 if the listener is invalid.
    std::uint16_t boundPort() const { return server_.port(); }

    // tc8::IPollableService — folded into the capture loop's drain set. The
    // listener fd when bound, or -1 (loop skips it) when the bind failed.
    int pollFd() const override { return server_.valid() ? server_.fd() : -1; }

    // Accept every currently-pending DUT connection, invoking the handler for
    // each. Runs on the capture-loop thread; non-blocking, returns once the
    // listener backlog is drained.
    void onReadable() override;

    // Count of connections accepted so far. Lets a test/case assert the DUT
    // actually connected. Written only in onReadable() (the capture thread), so
    // it needs no synchronisation.
    std::uint64_t accepted() const { return accepted_; }

  private:
    TcpServer server_;
    TcpAcceptHandler handler_;
    std::uint64_t accepted_ = 0;
};

}  // namespace tc8::stimulus
