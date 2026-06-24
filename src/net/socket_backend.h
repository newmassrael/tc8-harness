#pragma once

#include <cstddef>
#include <cstdint>

namespace tc8::net {

// A platform-neutral IPv4 endpoint (network byte order). A server core speaks
// this instead of sockaddr_in so it carries no OS socket headers — the
// SocketBackend translates to/from the platform's address type.
struct Endpoint {
    std::uint32_t addr_be = 0;
    std::uint16_t port = 0;
};

// The protocol-neutral I/O seam (ports & adapters): every socket operation a
// DUT-side conformance server needs from the network stack, expressed in raw
// terms (fds, byte counts, bool) with no application-protocol vocabulary. A
// Linux (POSIX syscalls) and an lwIP (socket API + core-API) adapter implement
// it once, and every server core written against this interface — the AUTOSAR
// testability ProtocolServer, the TC8 Upper Tester server — reuses the same
// adapters. Socket descriptors are opaque `int` handles the core stores and
// hands back; only the backend interprets them.
class SocketBackend {
public:
    virtual ~SocketBackend() = default;

    // Socket creation — fd >= 0 on success, -1 on failure.
    virtual int createUdp() = 0;
    virtual int createTcp() = 0;

    // Listener / bind setup.
    virtual void setReuseAddr(int fd) = 0;
    virtual void setBroadcast(int fd) = 0;
    virtual void setRecvTimeoutMs(int fd, int ms) = 0;
    // addr_be == 0 means "any address". true on success.
    virtual bool bindV4(int fd, std::uint32_t addr_be, std::uint16_t port) = 0;

    // Datagram I/O. recvFromV4: byte count, or < 0 on timeout/error (fills
    // `src` on success). sendToV4: byte count, or < 0 on failure.
    virtual int recvFromV4(int fd, void *buf, std::size_t len, Endpoint &src) = 0;
    virtual int sendToV4(int fd, const void *buf, std::size_t len, const Endpoint &dst) = 0;

    // Stream I/O. < 0 error, 0 peer close, else byte count.
    virtual int recv(int fd, void *buf, std::size_t len) = 0;
    virtual int send(int fd, const void *buf, std::size_t len) = 0;

    // Bounded active connect (non-blocking connect + wait up to timeout_ms,
    // fd left blocking on return). true on an established connection. The
    // backend captures whatever per-fd state a later abortive close needs.
    virtual bool connectBoundedV4(int fd, const Endpoint &dst, int timeout_ms) = 0;

    virtual bool listen(int fd, int backlog) = 0;
    // accept: new fd, or < 0 if none ready (fills `client` on success).
    virtual int accept(int fd, Endpoint &client) = 0;

    // how: 0 reception, 1 transmission, 2 both. true on success.
    virtual bool shutdown(int fd, int how) = 0;

    // Non-blocking toggle for the select-pump / drain loops.
    virtual void setNonBlocking(int fd, bool on) = 0;
    // < 0 error, 0 timeout, > 0 readable.
    virtual int waitReadable(int fd, int timeout_us) = 0;

    // Close (clears any per-fd backend state). closeWithAbort emits a RST.
    virtual void closeFd(int fd) = 0;
    virtual void closeWithAbort(int fd) = 0;
};

}  // namespace tc8::net
