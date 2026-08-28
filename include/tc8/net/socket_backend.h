#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "tc8/net/op_status.h"

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
// terms (fds, byte counts, bool, and — for the operations a stack may not have
// at all — the neutral OpStatus of op_status.h) with no application-protocol
// vocabulary. A
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

    // ── Capability operations (OpStatus, not bool) ──────────────────────────
    //
    // The six below are not socket plumbing: they are controls a stack may
    // structurally not have, and they fail for reasons a caller must tell apart
    // (tc8/net/op_status.h). Each names the statuses it can answer; a backend
    // returns the most specific one it can establish, never a vaguer stand-in.

    // Join the IPv4 multicast group `group_be` (network byte order) on a bound
    // UDP `fd`, receiving on the interface carrying `ifaddr_be` (0 = the default
    // interface). Unsupported on a stack built without multicast/IGMP (surfaced,
    // not silently dropped — a module that needs the group then degrades the way
    // it does on a failed bind); UnknownInterface when no interface carries
    // `ifaddr_be`; InvalidArgument when `group_be` is not a multicast address.
    virtual OpStatus joinMulticast(int fd, std::uint32_t group_be, std::uint32_t ifaddr_be) = 0;

    // Leave a multicast group previously joined on `fd` (the joinMulticast
    // counterpart), with the same status set.
    virtual OpStatus leaveMulticast(int fd, std::uint32_t group_be, std::uint32_t ifaddr_be) = 0;

    // Flush the dynamic (learned, non-permanent) IPv4 ARP/neighbor entries on
    // interface `ifname` — the network-stack reset a module backing an ARP
    // cache-control primitive needs, done via the stack's own API rather than
    // shelling out. Ok if the flush completed, including "nothing to flush";
    // otherwise UnknownInterface, NotPermitted where the delete is privileged,
    // or Unsupported on a stack exposing no such control (surfaced).
    // Per-interface, so it takes no fd.
    virtual OpStatus flushDynamicArp(const std::string &ifname) = 0;

    // Install a static (permanent) IPv4 ARP/neighbor entry on `ifname` mapping
    // `addr_be` (network byte order) to the 6-byte MAC at `mac` — the ARP-cache
    // pre-conditioning a module needs to suppress an ARP request for a peer it
    // already knows. UnknownInterface; InvalidArgument on a null `mac` or an
    // address not reachable via `ifname`; NotPermitted; or Unsupported on a stack
    // with no static-entry support (surfaced). Pairs with removeNeighbor; the
    // data plane stays the stack's own API, never a shell-out.
    virtual OpStatus addStaticNeighbor(const std::string &ifname, std::uint32_t addr_be,
                                       const std::uint8_t *mac) = 0;

    // Remove the single IPv4 neighbor entry for `addr_be` on `ifname`, whatever
    // its kind (static or learned) — the per-IP counterpart of flushDynamicArp,
    // used both to drop a pre-installed static entry and to force a re-ARP for one
    // peer. Ok including when no such entry exists (idempotent); otherwise
    // UnknownInterface, InvalidArgument, NotPermitted, or Unsupported where the
    // stack cannot remove an entry of that kind.
    virtual OpStatus removeNeighbor(const std::string &ifname, std::uint32_t addr_be) = 0;

    // Set the base reachable time (milliseconds) for learned IPv4 neighbor entries
    // on `ifname` — the ARP-cache aging control a module uses to drive entries
    // stale and provoke revalidation. UnknownInterface; InvalidArgument on a
    // negative time; NotPermitted where the knob is privileged; or Unsupported on
    // a stack whose aging is fixed at compile time and cannot be changed at
    // runtime (surfaced, not silently accepted — a permanent target property and
    // a caller-side one are different answers, and only the caller-side one is
    // worth a retry). The caller restores the prior value if it needs to.
    virtual OpStatus setNeighborReachableMs(const std::string &ifname, int reachable_ms) = 0;

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
