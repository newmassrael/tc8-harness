#include "stimulus/tx_observer.h"

#include <atomic>
#include <thread>

#include <netinet/in.h>
#include <sys/socket.h>

namespace tc8::stimulus {
namespace {

// Set by the runner before any stimulus and cleared when the case ends. Atomic, with a
// count of reports in flight, because the clearing is not ordered against every sender:
// a responder thread, or a thread a case detached for a burst, may be inside a report
// when the case ends and the observer behind the pointer is destroyed. Clearing waits
// for them (setTxObserver), so a report never reaches a destroyed observer.
std::atomic<ITxObserver *> g_observer{nullptr};
std::atomic<int>           g_in_flight{0};

// The outermost active scope's name on this thread, or nullptr. Per thread because a
// scope names the emitter running on THAT thread; a responder thread sending while the
// capture thread is inside an emitter is not that emitter's send.
thread_local const char *t_emitter = nullptr;

// The innermost active TxSpecStep's number on this thread, or kNoSpecStep.
thread_local int t_spec_step = kNoSpecStep;

// The innermost active TxConnectSteps on this thread; inactive without one.
struct ConnectSteps {
    bool active = false;
    int  syn = kNoSpecStep;
    int  ack = kNoSpecStep;
};
thread_local ConnectSteps t_connect_steps;

void deliver(const char *transport, std::string_view iface, std::uint32_t dst_ip_be,
             std::uint16_t dst_port, std::uint16_t src_port, std::size_t bytes,
             int spec_step, std::string_view action = {}) {
    g_in_flight.fetch_add(1);
    if (ITxObserver *observer = g_observer.load()) {
        TxEvent ev;
        ev.emitter = t_emitter != nullptr ? std::string_view{t_emitter} : std::string_view{};
        ev.transport = transport;
        ev.action = action;
        ev.iface = iface;
        ev.dst_ip_be = dst_ip_be;
        ev.dst_port = dst_port;
        ev.src_port = src_port;
        ev.bytes = bytes;
        ev.spec_step = spec_step;
        observer->onTx(ev);
    }
    g_in_flight.fetch_sub(1);
}

// The two ends of a connected IPv4 socket. False when either cannot be read, which
// leaves the report without a destination rather than with a wrong one.
bool connectionEnds(int fd, sockaddr_in &peer, sockaddr_in &local) {
    socklen_t len = sizeof(peer);
    if (::getpeername(fd, reinterpret_cast<sockaddr *>(&peer), &len) != 0 ||
        peer.sin_family != AF_INET) {
        return false;
    }
    len = sizeof(local);
    return ::getsockname(fd, reinterpret_cast<sockaddr *>(&local), &len) == 0 &&
           local.sin_family == AF_INET;
}

void deliverOnConnection(const char *transport, std::string_view iface, int fd,
                         std::size_t bytes, int spec_step) {
    sockaddr_in peer{};
    sockaddr_in local{};
    if (!connectionEnds(fd, peer, local)) {
        // The send happened; where it went is unknown. Reported without a destination.
        deliver(transport, iface, 0, 0, 0, bytes, spec_step);
        return;
    }
    deliver(transport, iface, peer.sin_addr.s_addr, ntohs(peer.sin_port),
            ntohs(local.sin_port), bytes, spec_step);
}

}  // namespace

void setTxObserver(ITxObserver *observer) {
    g_observer.store(observer);
    if (observer == nullptr) {
        // A report that read the old pointer before the store is counted here; one that
        // starts after it reads null. Sequentially consistent, so the two cannot both
        // be missed.
        while (g_in_flight.load() != 0) {
            std::this_thread::yield();
        }
    }
}

void reportTx(const char *transport, std::string_view iface, std::uint32_t dst_ip_be,
              std::uint16_t dst_port, std::size_t bytes) {
    if (g_observer.load(std::memory_order_relaxed) == nullptr) {
        return;
    }
    deliver(transport, iface, dst_ip_be, dst_port, 0, bytes, t_spec_step);
}

void reportTxConnected(const char *transport, int fd, std::size_t bytes,
                       std::string_view iface) {
    // Not even the socket lookups without an observer: a send costs what it always did.
    if (g_observer.load(std::memory_order_relaxed) == nullptr) {
        return;
    }
    deliverOnConnection(transport, iface, fd, bytes, t_spec_step);
}

void reportTcpConnected(std::string_view iface, int fd) {
    if (g_observer.load(std::memory_order_relaxed) == nullptr) {
        return;
    }
    const ConnectSteps &steps = t_connect_steps;
    deliverOnConnection("tcp_connect", iface, fd, 0, steps.active ? steps.syn : t_spec_step);
    deliverOnConnection("tcp_connect_ack", iface, fd, 0,
                        steps.active ? steps.ack : t_spec_step);
}

void reportTcpAccepted(int fd, std::uint32_t peer_ip_be, std::uint16_t peer_port) {
    if (g_observer.load(std::memory_order_relaxed) == nullptr) {
        return;
    }
    // The local end survives a reset (only the peer is gone), so it is read apart from
    // the peer rather than dropped with it.
    std::uint16_t local_port = 0;
    sockaddr_in local{};
    socklen_t len = sizeof(local);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&local), &len) == 0 &&
        local.sin_family == AF_INET) {
        local_port = ntohs(local.sin_port);
    }
    deliver("tcp_accept", {}, peer_ip_be, peer_port, local_port, 0, t_spec_step);
}

void reportTcpReset(std::string_view iface, std::uint32_t dst_ip_be, std::uint16_t dst_port,
                    std::uint16_t src_port) {
    if (g_observer.load(std::memory_order_relaxed) == nullptr) {
        return;
    }
    deliver("tcp_reset", iface, dst_ip_be, dst_port, src_port, 0, t_spec_step);
}

void reportTcpRefusal(std::string_view iface, std::uint16_t port) {
    if (g_observer.load(std::memory_order_relaxed) == nullptr) {
        return;
    }
    deliver("tcp_refuse", iface, 0, 0, port, 0, t_spec_step);
}

void reportTesterAction(std::string_view what) {
    if (g_observer.load(std::memory_order_relaxed) == nullptr) {
        return;
    }
    deliver("tester_action", {}, 0, 0, 0, 0, t_spec_step, what);
}

TxScope::TxScope(const char *emitter) : owns_(t_emitter == nullptr) {
    if (owns_) {
        t_emitter = emitter;
    }
}

TxScope::~TxScope() {
    if (owns_) {
        t_emitter = nullptr;
    }
}

TxSpecStep::TxSpecStep(int step) : previous_(t_spec_step) {
    t_spec_step = step;
}

TxSpecStep::~TxSpecStep() {
    t_spec_step = previous_;
}

TxConnectSteps::TxConnectSteps(int syn, int ack)
    : previous_active_(t_connect_steps.active),
      previous_syn_(t_connect_steps.syn),
      previous_ack_(t_connect_steps.ack) {
    t_connect_steps = ConnectSteps{true, syn, ack};
}

TxConnectSteps::~TxConnectSteps() {
    t_connect_steps = ConnectSteps{previous_active_, previous_syn_, previous_ack_};
}

}  // namespace tc8::stimulus
