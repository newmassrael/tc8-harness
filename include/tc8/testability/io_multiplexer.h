#pragma once

#include <cstddef>
#include <memory>
#include <vector>

namespace tc8::testability {

// A cross-thread wakeup for a poll() loop, modeled as the resource it is: it owns
// its underlying fd(s) and frees them on destruction (RAII). A Reactor holds one
// by unique_ptr, places pollFd() in poll()'s set, calls signal() from any thread to
// break a blocked poll(), and drain()s it on the poll thread once readable. A POSIX
// backend wraps an eventfd; an lwIP backend wraps a loopback UDP socket pair — the
// shape never leaks into the consumer, which sees only this interface, so there is
// no fd to "remember" and no paired-fd bookkeeping outside the object.
class Waker {
public:
    virtual ~Waker() = default;
    virtual int pollFd() const = 0;  // the fd to include in poll()'s set
    virtual void signal() = 0;        // any thread: make pollFd() readable
    virtual void drain() = 0;         // poll thread: consume pending signal(s)
};

// The I/O multiplexing capability a Reactor needs from a backend: a multi-fd
// readiness wait plus a cross-thread Waker. Segregated from the data-plane
// net::SocketBackend (which a module uses) and from the testability primitives, so
// the Reactor depends only on this narrow surface — it knows nothing of sockets'
// application semantics or of the testability protocol. A backend's SocketBackend
// adapter implements this port; the concrete Reactor (testability/reactor.h) is the
// only consumer, and it stays out of the adapter's include graph.
class IoMultiplexer {
public:
    virtual ~IoMultiplexer() = default;

    // Block until an fd in `read_fds[0..read_n)` is readable, an fd in
    // `write_fds[0..write_n)` is writable, or `timeout_ms` elapses (`timeout_ms` < 0 =
    // indefinite). `readable` and `writable` are cleared and filled with the ready
    // subsets. Returns the total ready count (0 on timeout), or -1 on error.
    //
    // A socket whose connection attempt failed counts as writable: that is the only
    // readiness a pending connect has, and its handler reads the failure from it.
    virtual int poll(const int *read_fds, std::size_t read_n, const int *write_fds,
                     std::size_t write_n, int timeout_ms, std::vector<int> &readable,
                     std::vector<int> &writable) = 0;

    // A Waker to include in poll()'s set, or nullptr if this backend has none (the
    // Reactor then falls back to its bounded liveness wait). Caller owns it.
    virtual std::unique_ptr<Waker> createWaker() = 0;
};

}  // namespace tc8::testability
