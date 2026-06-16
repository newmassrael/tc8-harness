#pragma once

#include <cstddef>
#include <cstdint>

#include "net/socket_backend.h"

namespace tc8::ut {

// The four TCP-info fields the §4.8.6.11 RETRANSMISSION_TO cluster verdicts on
// (OpQueryTcpInfo 0x13) and the established-state probe (OpQueryTcpEstablished
// 0x05) read. `state` uses the frozen wire numbering in upper_tester_protocol.h
// (kTcpState*), which equals the Linux kernel's TCP FSM numbering — the POSIX
// probe passes tcpi_state through verbatim (static_asserting the equivalence),
// a non-Linux stack translates its own enum to these constants.
struct TcpInfo {
    std::uint8_t  state       = 0;  // kTcpState* (1 = ESTABLISHED, ...)
    std::uint32_t rto_us      = 0;  // retransmission timeout, microseconds
    std::uint8_t  retransmits = 0;  // retransmits fired since connection start
    std::uint32_t unacked     = 0;  // segments outstanding
};

// The Upper-Tester-specific extension of the platform stack seam: the operations
// the UT server needs that are NOT plain socket primitives (those live in
// tc8::net::SocketBackend, shared with the testability server) AND are not
// expressible across platforms the same way — TCP-state introspection, the
// out-of-band receive, and the original-destination datagram receive used by the
// §4.4 ADDRESSING data listener. Segregated from SocketBackend (ISP): the
// testability server has none of these, so it depends on the generic seam alone.
// A Linux (POSIX) and an lwIP adapter implement this once; the core is written
// against it. Socket descriptors are the same opaque `int` handles the core
// stores via SocketBackend.
class StackProbe {
public:
    virtual ~StackProbe() = default;

    // OpQueryTcpInfo / OpQueryTcpEstablished: read the connection's TCP_INFO.
    // true on success (fills `out`); false if the stack cannot report it.
    virtual bool queryTcpInfo(int fd, TcpInfo &out) = 0;

    // OpReceiveTcpDataOob: drain up to `len` urgent bytes within `timeout_ms`.
    // Byte count read (>= 0), or < 0 on error. A stack without an out-of-band
    // path returns 0 (surfaced as an empty receive, not an error).
    virtual int recvOob(int fd, void *buf, std::size_t len, int timeout_ms) = 0;

    // §4.4 ADDRESSING data listener: a UDP socket that reports each datagram's
    // ORIGINAL wire destination (IP_PKTINFO on Linux), so the core can apply the
    // RFC 1122 directed-broadcast / multicast silent-discard. createUdp + bind
    // are not enough — the original-destination ancillary path is platform
    // specific, so the adapter owns the socket's creation + option setup.
    // Returns a bound fd ready for recvWithOriginalDstV4, or -1 on failure.
    virtual int openOriginalDstListenerV4(std::uint16_t port) = 0;

    // Receive one datagram on a socket from openOriginalDstListenerV4, filling
    // `src` and the original wire destination `orig_dst_be` (network byte order).
    // Byte count (the TRUE datagram length, which may exceed `len`), or < 0 on
    // timeout / error.
    virtual int recvWithOriginalDstV4(int fd, void *buf, std::size_t len,
                                      net::Endpoint &src, std::uint32_t &orig_dst_be) = 0;
};

}  // namespace tc8::ut
