#pragma once

#include <cstdint>
#include <string_view>

#include "stimulus/endpoint.h"  // Endpoint — the DUT endpoint to connect to (SSOT).

namespace tc8::stimulus {

// Open a TCP socket, bind it to a source port (ephemeral unless `source_port` names
// one) on `iface`'s primary IPv4
// (or `source_ip_be` if non-zero — a configured alias, for a second client the DUT
// discriminates by source IP), and connect it to `dst`. This is the shared
// bind->connect prologue every tester-side TCP originator needs — the TCP analog of
// udp_emit's openBoundUdpSocket — so the RPC method-request emitters and the
// reliable-subscribe session share one implementation instead of hand-copying it.
//
// Returns the connected fd (>= 0) or a negative errno-derived sentinel, each logged
// to stderr: -1 socket(), -2 interface has no IPv4 address, -3 bind(), -4 connect().
// On success, writes the source port (host order) to `*out_local_port` when non-null
// (the connection identity a reliable Subscribe advertises). `nonblocking` sets
// O_NONBLOCK after the (blocking) connect, for a caller that drains the socket from a
// non-blocking poll loop.
//
// `source_port` names the tester's source port. 0 leaves it to the kernel (an
// ephemeral port). Any other value is bound before the connect, with SO_REUSEADDR so a
// case can reconnect from the port a connection of its own just closed. A DUT that keys
// its connection table on the peer's source port (taken from a configured database,
// with no connection id in the application header) sees an unknown peer from any other
// port; a firewall or ACL rule that pins the port does the same. A port that cannot be
// bound (in use, or privileged for an unprivileged tester) is -3, so the case records an
// unperformed stimulus and ends inconclusive: nothing was sent, and the DUT is not at
// fault. A reconnect to the same four-tuple while the closed connection is still in
// TIME-WAIT is refused by the kernel at the connect (-4), for the same reason.
int connectTcpFromIface(std::string_view iface, const Endpoint &dst,
                        std::uint32_t source_ip_be = 0,
                        std::uint16_t *out_local_port = nullptr,
                        bool nonblocking = false,
                        std::uint16_t source_port = 0);

}  // namespace tc8::stimulus
