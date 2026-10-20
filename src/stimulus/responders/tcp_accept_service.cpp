#include "stimulus/tcp_accept_service.h"

#include <chrono>
#include <optional>
#include <utility>

namespace tc8::stimulus {

namespace {
// listen() backlog for the autonomous accept path. The DUT may open more than
// one reliable connection (e.g. two service instances) close together, so give
// the kernel queue headroom over the synchronous default of 1 — a queued SYN is
// accepted on the next drain rather than dropped.
constexpr int kAutonomousAcceptBacklog = 8;
}  // namespace

TcpAcceptService::TcpAcceptService(std::string_view iface, std::uint16_t port,
                                   TcpAcceptHandler handler, int accept_step, int close_step)
    : TcpAcceptService(iface, port, std::move(handler),
                       TcpAcceptStepFn([accept_step](std::uint64_t) { return accept_step; }),
                       close_step) {}

TcpAcceptService::TcpAcceptService(std::string_view iface, std::uint16_t port,
                                   TcpAcceptHandler handler, TcpAcceptStepFn accept_step,
                                   int close_step)
    // The listener is created non-blocking with a deeper backlog: non-blocking so
    // onReadable()'s accept never stalls the single capture thread (the
    // IPollableService contract), and the backlog so a burst of DUT connects is
    // queued rather than refused. Both are intrinsic to the socket via
    // openTcpListener, not patched on afterwards.
    : server_(iface, port, /*non_blocking=*/true, /*backlog=*/kAutonomousAcceptBacklog),
      handler_(std::move(handler)),
      accept_step_(std::move(accept_step)),
      close_step_(close_step) {}

void TcpAcceptService::onReadable() {
    if (!server_.valid()) {
        return;
    }
    // Drain every currently-pending connection without blocking: acceptOne(0)
    // polls with a 0 ms timeout and returns std::nullopt the moment accept would
    // block (backlog empty, or the benign poll->accept race), ending the loop.
    // Each accepted connection's ownership moves into the handler, which decides
    // the app-layer behaviour. A connection the handler does not retain destructs
    // at the end of the call. No synchronisation: capture thread only.
    while (true) {
        std::optional<TcpConnection> conn;
        {
            // The accept's step covers its own report only: what the handler sends over
            // the connection is a step of its own, not the handshake's. Chosen for the
            // accept about to happen, before it, since the report is made inside it; a
            // drain that finds nothing to accept asks and uses nothing.
            const TxSpecStep step(accept_step_ ? accept_step_(accepted_ + 1) : kNoSpecStep);
            conn = server_.acceptOne(std::chrono::milliseconds(0));
        }
        if (!conn) {
            break;
        }
        ++accepted_;
        if (handler_) {
            handler_(std::move(*conn));
        }
    }
}

}  // namespace tc8::stimulus
