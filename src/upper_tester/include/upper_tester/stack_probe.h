#pragma once

#include <cstddef>
#include <cstdint>

#include "tc8/net/socket_backend.h"
#include "tc8/net/tcp_info_reader.h"

namespace tc8::ut {

// The four TCP-info fields the §4.8.6.11 RETRANSMISSION_TO cluster verdicts on
// (OpQueryTcpInfo 0x13) and the established-state probe (OpQueryTcpEstablished
// 0x05) read. net::TcpInfo owns them, so a middleware module reads the same fields
// without the Upper Tester.
using TcpInfo = net::TcpInfo;

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
//
// queryTcpInfo, for OpQueryTcpInfo and OpQueryTcpEstablished, comes from
// net::TcpInfoReader.
class StackProbe : public net::TcpInfoReader {
public:
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
