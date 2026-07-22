#include "stimulus/tcp_accept_service.h"

#include <chrono>
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
                                   TcpAcceptHandler handler)
    // The listener is created non-blocking with a deeper backlog: non-blocking so
    // onReadable()'s accept never stalls the single capture thread (the
    // IPollableService contract), and the backlog so a burst of DUT connects is
    // queued rather than refused. Both are intrinsic to the socket via
    // openTcpListener, not patched on afterwards.
    : server_(iface, port, /*non_blocking=*/true, /*backlog=*/kAutonomousAcceptBacklog),
      handler_(std::move(handler)) {}

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
    while (auto conn = server_.acceptOne(std::chrono::milliseconds(0))) {
        ++accepted_;
        if (handler_) {
            handler_(std::move(*conn));
        }
    }
}

}  // namespace tc8::stimulus
