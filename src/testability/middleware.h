#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include "net/socket_backend.h"
#include "tc8/testability_protocol.h"

// Stateful Upper-Tester extension seam (PRS_TPSP §6.6). The built-in groups and
// registerPrimitive() handlers in ProtocolServer are request/response only; a
// MiddlewareModule additionally holds state across primitives and runs
// background activity (periodic transmission, asynchronous Events). It is the
// host surface an out-of-tree OEM group (network management, signal-based
// command/control, ...) attaches to — the OEM supplies the module and its
// configuration; this core hosts it and knows nothing OEM-specific.
//
// Concurrency contract: every module callback (onStart / onPrimitive / onStop /
// onStartTest / onEndTest and every timer / posted task) runs on the module's
// own dedicated executor, serialized run-to-completion. A module therefore needs
// no internal locking — it is single-threaded by construction.

namespace tc8::testability {

using net::Endpoint;

// Opaque cancellation handle for a scheduled timer. The default-constructed /
// zero value is never returned by the scheduler and denotes "no timer".
enum class TimerId : std::uint64_t {};

class MiddlewareContext;

// A stateful service group supplied out-of-tree (PRS_TPSP §6.6 extension).
class MiddlewareModule {
public:
    virtual ~MiddlewareModule() = default;

    // The service group ID(s) this module owns (PRS_TPSP §6.9). Every primitive
    // whose GID is in this set is routed to onPrimitive(), consulted before the
    // built-in groups. Read once at registerModule(); must be stable.
    virtual std::vector<std::uint8_t> groups() const = 0;

    // Called once when the server starts, before it serves any request. Capture
    // `ctx` (valid until onStop() returns) to open data-plane sockets and arm
    // timers. Runs on the module executor.
    virtual void onStart(MiddlewareContext &ctx) = 0;

    // Called once during stop()/dtor, after the last primitive/timer. Release
    // resources obtained from the context. Runs on the module executor.
    virtual void onStop() = 0;

    // A request for one of this module's GIDs. Fill `rid_out` + `resp_dat` for
    // the single synchronous Response (same contract as ProtocolServer's
    // SpHandler). Must be non-blocking (PRS_TPSP §6.2): arm a timer or emit a
    // later Event instead of waiting. An unknown PID under an owned GID should
    // set rid_out = kRidENtf. Runs on the module executor.
    virtual void onPrimitive(const Header &req, const std::uint8_t *dat, std::size_t dat_len,
                             const Endpoint &peer, std::uint8_t &rid_out,
                             std::vector<std::uint8_t> &resp_dat) = 0;

    // PRS_TPSP §6.10.1 trace boundaries (default no-ops). onEndTest() returns the
    // module to its inactive state — stop periodic activity, clear accumulated
    // buffers — but it stays registered. Both run on the module executor.
    virtual void onStartTest() {}
    virtual void onEndTest() {}
};

// The host services a module reaches at run time, injected at onStart(). Every
// callback scheduled here is delivered on the module executor, serialized with
// onPrimitive() — so module state is shared across them without locking.
class MiddlewareContext {
public:
    virtual ~MiddlewareContext() = default;

    // The shared socket/stack adapter (the same backend the core uses). A module
    // opens its own data-plane sockets here — never a raw OS API, so it stays
    // neutral across the POSIX and lwIP backends.
    virtual net::SocketBackend &backend() = 0;

    // Periodic timer: invoke `fn` every `period` until cancel() / onStop(). The
    // first fire is one `period` out. Delivered on the module executor.
    virtual TimerId scheduleEvery(std::chrono::milliseconds period, std::function<void()> fn) = 0;

    // One-shot timer after `delay`, delivered on the module executor.
    virtual TimerId scheduleOnce(std::chrono::milliseconds delay, std::function<void()> fn) = 0;

    // Cancel a timer (no-op if it already fired, was cancelled, or never existed).
    virtual void cancel(TimerId id) = 0;

    // Emit an asynchronous testability EVENT (PRS_TPSP §6.2, EVB set, TID
    // kTidEvent) for (gid,pid) to the test system that issued this module's most
    // recent primitive (the requester per PRS_TPSP §6.2). `dat` is the event DAT.
    virtual void emitEvent(std::uint8_t gid, std::uint8_t pid,
                           const std::vector<std::uint8_t> &dat) = 0;

    // Marshal `fn` onto the module executor (e.g. to hand a result back from a
    // foreign thread the module itself spawned).
    virtual void post(std::function<void()> fn) = 0;

    // The steady clock the scheduler uses.
    virtual std::chrono::steady_clock::time_point now() const = 0;
};

}  // namespace tc8::testability
