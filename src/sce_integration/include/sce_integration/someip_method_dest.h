#pragma once

#include <cstdint>

#include "sce_integration/test_config.h"
#include "stimulus/someip_rpc_builder.h"

// Single source of truth for a SOME/IP Method Request's DUT endpoint.
//
// The endpoint the DUT serves is configured via `--expect` (`dut_iface_ip`
// plus `udp_port` / `tcp_port`, which smoke-test.sh derives from the DUT's
// own vsomeip.json via tools/dut_identity.py — see `TC8_DUT_EXPECT`). Cases
// derive the destination from `cfg.someip` instead of restating the
// conformance-topology literal, so a run against a DUT at a non-default
// address works without touching any case.
//
// No literal fallback: an unconfigured field stays 0, so a misconfigured run
// targets 0.0.0.0:0 and fails loud on connect rather than silently hitting a
// baked-in address. `MethodEndpoint` therefore carries no implicit
// default (cf. someip_rpc_builder.h) — the endpoint is always sourced here.
//
// Byte order matches `MethodEndpoint`: `dut_iface_ip` is network
// byte order (parsed by `parseIpv4Dotted` straight from `inet_pton`, the same
// convention `ipv4_be` carries onto `sockaddr_in::sin_addr`), and the ports
// are host order (the emitter applies `htons`).

namespace tc8::sce {

// Spawn-variant Method Request ports the base `--expect` surface does not
// carry: tools/dut_identity.py derives the offered endpoint from `services[0]`
// of the base vsomeip.json only, so the multi-instance / multi-service variant
// ports have no config channel and are named here beside that fact. Passed as
// the `port_override` argument; the DUT IP still derives from `cfg`.
namespace someip {
inline constexpr std::uint16_t kSi2UdpPort = 30506;       // SERVICE-ID-2 unreliable (vsomeip-multi-service.json)
inline constexpr std::uint16_t kSi1Inst2UdpPort = 30504;  // SERVICE-ID-1 instance 0x0002 unreliable (vsomeip-multi-instance.json)
inline constexpr std::uint16_t kSi1Inst2TcpPort = 30503;  // SERVICE-ID-1 instance 0x0002 reliable (vsomeip-multi-instance.json)
}  // namespace someip

namespace detail {
// Compose the destination from the configured DUT IP and a port.
// `port_override` (a `someip::kSi*` constant) names a spawn-variant port the
// base surface does not carry; 0 means "use the configured transport port".
inline ::tc8::stimulus::MethodEndpoint
methodDest(std::uint32_t dut_iface_ip_be, std::uint16_t configured_port,
           std::uint16_t port_override) {
    ::tc8::stimulus::MethodEndpoint dest{};
    dest.ipv4_be = dut_iface_ip_be;
    dest.port = port_override != 0 ? port_override : configured_port;
    return dest;
}
}  // namespace detail

// DUT Method Request endpoint for the UNRELIABLE (UDP) transport.
inline ::tc8::stimulus::MethodEndpoint
someipUdpMethodDest(const ::tc8::TestConfig &cfg, std::uint16_t port_override = 0) {
    return detail::methodDest(cfg.someip.dut_iface_ip, cfg.someip.udp_port, port_override);
}

// DUT Method Request endpoint for the RELIABLE (TCP) transport.
inline ::tc8::stimulus::MethodEndpoint
someipTcpMethodDest(const ::tc8::TestConfig &cfg, std::uint16_t port_override = 0) {
    return detail::methodDest(cfg.someip.dut_iface_ip, cfg.someip.tcp_port, port_override);
}

}  // namespace tc8::sce
