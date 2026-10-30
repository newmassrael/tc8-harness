#pragma once

#include <cstdint>
#include <string_view>

#include "stimulus/endpoint.h"  // Endpoint — the DUT endpoint to connect to (SSOT).

namespace tc8::stimulus {

// What a tester-side TCP originator may choose about its end of the connection. One struct
// instead of a growing positional list: a caller names only what it changes, and a new
// choice is a new field, not another default argument every call site must count past.
struct TcpConnectOptions {
    // The tester's source address (network byte order): a configured alias, for a second
    // client the DUT discriminates by source IP. 0 is `iface`'s primary IPv4.
    std::uint32_t source_ip_be = 0;
    // The tester's source port. 0 leaves it to the kernel (an ephemeral port). Any other
    // value is bound before the connect, with SO_REUSEADDR so a case can reconnect from the
    // port a connection of its own just closed. A DUT that keys its connection table on the
    // peer's source port (taken from a configured database, with no connection id in the
    // application header) sees an unknown peer from any other port; a firewall or ACL rule
    // that pins the port does the same.
    std::uint16_t source_port = 0;
    // Set O_NONBLOCK after the (blocking) connect, for a caller that drains the socket
    // from a non-blocking poll loop.
    bool nonblocking = false;
    // Treat a connect that ends on the PEER's verdict as the thing the case measures, not as
    // a stimulus the tester failed to perform. The default is the second, which is what a
    // preamble wants: an RPC or a subscribe that cannot connect has nothing to grade, and the
    // run ends inconclusive. A case whose subject IS the connect (a listener that must accept,
    // refuse, or stay silent) sets this, so a refused or unanswered SYN is a performed
    // stimulus with a result (TcpConnectEnd) and the verdict is the case's to give.
    //
    // The peer's verdicts are ECONNREFUSED (an RST answered the SYN), ECONNRESET and
    // ETIMEDOUT, and the end of `connect_timeout_ms`. Every other failure stays the tester's:
    // EHOSTUNREACH and ENETUNREACH are raised for a missing route or an unresolved neighbour
    // as well as for an ICMP error, so they do not show a SYN reached the DUT; EADDRNOTAVAIL
    // is a closed connection still in TIME-WAIT on the same four-tuple.
    bool peer_verdict_is_outcome = false;
    // Bound the wait for the handshake, in milliseconds. 0 leaves it to the kernel, which
    // retransmits the SYN for about two minutes. A case that asserts the DUT stays silent
    // sets it to its own window, so the run does not outlast the window to learn the answer.
    // Elapsing is a TcpConnectEnd::kTimedOut, which is the peer's verdict only with
    // `peer_verdict_is_outcome`; without it the connect fails as it does today.
    std::uint32_t connect_timeout_ms = 0;
};

// How a connect the tester made ended.
enum class TcpConnectEnd {
    kEstablished,    // the handshake completed; the result holds the fd
    kNotPerformed,   // the tester could not do its part; recorded as an unperformed stimulus
    kRefused,        // an RST answered the SYN
    kReset,          // the connection was reset during the handshake
    kTimedOut,       // no answer: the kernel gave up, or `connect_timeout_ms` elapsed
};

// Returned in place of the sentinel when a connect ended on the peer's verdict and the
// caller asked for it as an outcome (TcpConnectOptions::peer_verdict_is_outcome).
inline constexpr int kTcpConnectPeerVerdict = -5;

struct TcpConnectResult {
    // The connected fd (>= 0), or the sentinel connectTcpFromIface documents.
    int fd = -1;
    TcpConnectEnd end = TcpConnectEnd::kNotPerformed;
};

// Open a TCP socket, bind it on `iface` as `options` say, and connect it to `dst`. This is
// the shared bind->connect prologue every tester-side TCP originator needs — the TCP analog
// of udp_emit's openBoundUdpSocket — so the RPC method-request emitters and the
// reliable-subscribe session share one implementation instead of hand-copying it.
//
// Returns the connected fd (>= 0) or a negative errno-derived sentinel, each logged
// to stderr: -1 socket(), -2 interface has no IPv4 address, -3 bind(), -4 connect(), and
// -5 (kTcpConnectPeerVerdict) a connect the peer refused, reset or left unanswered, which
// only a caller that set `peer_verdict_is_outcome` sees. Every sentinel but -5 records an
// unperformed stimulus; -5 records none, because the SYN went out. A caller that must tell
// the ends of the peer's verdict apart calls connectTcp.
// On success, writes the source port (host order) to `*out_local_port` when non-null
// (the connection identity a reliable Subscribe advertises). It is written for -5 as well:
// the port is bound before the connect, and the SYN carried it.
//
// A source port that cannot be bound (in use, or privileged for an unprivileged tester) is
// -3, so the case records an unperformed stimulus and ends inconclusive: nothing was sent,
// and the DUT is not at fault. A reconnect to the same four-tuple while the closed
// connection is still in TIME-WAIT is refused by the kernel at the connect (-4), for the
// same reason.
int connectTcpFromIface(std::string_view iface, const Endpoint &dst,
                        const TcpConnectOptions &options = {},
                        std::uint16_t *out_local_port = nullptr);

// The same connect, with how it ended named. `connectTcpFromIface` is this call reduced to
// its fd; the three preamble helpers keep that form, and a case measuring the connect uses
// this one.
TcpConnectResult connectTcp(std::string_view iface, const Endpoint &dst,
                            const TcpConnectOptions &options = {},
                            std::uint16_t *out_local_port = nullptr);

}  // namespace tc8::stimulus
