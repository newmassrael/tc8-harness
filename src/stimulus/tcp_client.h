#pragma once

#include <cstdint>
#include <string_view>

#include "stimulus/endpoint.h"  // Endpoint — the DUT endpoint to connect to (SSOT).

namespace tc8::stimulus {

// Open a TCP socket, bind it to an ephemeral source port on `iface`'s primary IPv4
// (or `source_ip_be` if non-zero — a configured alias, for a second client the DUT
// discriminates by source IP), and connect it to `dst`. This is the shared
// bind->connect prologue every tester-side TCP originator needs — the TCP analog of
// udp_emit's openBoundUdpSocket — so the RPC method-request emitters and the
// reliable-subscribe session share one implementation instead of hand-copying it.
//
// Returns the connected fd (>= 0) or a negative errno-derived sentinel, each logged
// to stderr: -1 socket(), -2 interface has no IPv4 address, -3 bind(), -4 connect().
// On success, writes the kernel-assigned source port (host order) to
// `*out_local_port` when non-null (the connection identity a reliable Subscribe
// advertises). `nonblocking` sets O_NONBLOCK after the (blocking) connect, for a
// caller that drains the socket from a non-blocking poll loop.
int connectTcpFromIface(std::string_view iface, const Endpoint &dst,
                        std::uint32_t source_ip_be = 0,
                        std::uint16_t *out_local_port = nullptr,
                        bool nonblocking = false);

}  // namespace tc8::stimulus
