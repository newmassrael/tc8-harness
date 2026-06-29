#pragma once

#include <cstdint>

namespace tc8::stimulus {

// The canonical IPv4 ip:port value type — one SSOT for the 2-field endpoint POD
// that the SOME/IP method builders (as `MethodEndpoint`), the TCP server
// (`TcpConnection::peer()`), and any other transport primitive share, instead of
// each re-declaring its own. A leaf header (cstdint only), so a consumer that
// needs just the endpoint shape (e.g. tcp_server.h) does not pull in a builder's
// full declaration surface.
//
// Both fields default to 0, which is an UNCONFIGURED sentinel, not a usable
// address: callers that send to an Endpoint derive it from topology/runtime
// (cfg.someip, or a captured frame's source) — a 0.0.0.0:0 fails loud rather than
// silently targeting a hardcoded host.
struct Endpoint {
    // IPv4 in network byte order (matches `Ipv4Endpoint::ipv4_be` and
    // cfg.someip.dut_iface_ip, both NBO via inet_pton).
    std::uint32_t ipv4_be = 0;
    // Host order; the emitter applies htons.
    std::uint16_t port = 0;
};

}  // namespace tc8::stimulus
