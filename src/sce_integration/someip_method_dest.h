#pragma once

#include <cstdint>

#include "sce_integration/test_config.h"
#include "stimulus/someip_rpc_builder.h"

// Single source of truth for a SOME/IP Method Request's DUT endpoint.
//
// The endpoint the DUT actually serves is already configured via `--expect`
// (`dut_iface_ip` plus `udp_port` / `tcp_port`, which smoke-test.sh derives
// from the DUT's own vsomeip.json via tools/dut_identity.py — see
// `TC8_DUT_EXPECT`). Cases therefore derive the Method Request destination
// from `cfg.someip` rather than restating the 172.16.0.2:30502
// conformance-topology literal, so the DUT endpoint stays one fact with one
// source and a run against a DUT at a non-default address works without
// touching any case.
//
// Byte order matches `MethodRequestDestination` exactly: `dut_iface_ip` is
// parsed by `parseIpv4Dotted` straight from `inet_pton` (network byte order,
// the same convention `ipv4_be` carries onto `sockaddr_in::sin_addr`), and
// the port fields are host order (the emitter applies `htons`). The values
// are therefore assigned through unchanged.
//
// `port_override` names a port that is NOT the configured `services[0]`
// endpoint — the multi-instance / multi-service spawned vsomeip variants
// (e.g. ports 30503 / 30504 / 30506) whose endpoints the base `--expect`
// surface does not carry. Pass 0 (the default) to inherit the configured
// port.
//
// When a field is unset (0 — e.g. a manual run with no `--expect`), the
// stimulus-layer `MethodRequestDestination` default is preserved, so the
// builder stays usable standalone exactly as before.

namespace tc8::sce {

inline ::tc8::stimulus::MethodRequestDestination
someipUdpMethodDest(const ::tc8::TestConfig &cfg, std::uint16_t port_override = 0) {
    ::tc8::stimulus::MethodRequestDestination dest{};
    if (cfg.someip.dut_iface_ip != 0) {
        dest.ipv4_be = cfg.someip.dut_iface_ip;
    }
    if (port_override != 0) {
        dest.port = port_override;
    } else if (cfg.someip.udp_port != 0) {
        dest.port = cfg.someip.udp_port;
    }
    return dest;
}

inline ::tc8::stimulus::MethodRequestDestination
someipTcpMethodDest(const ::tc8::TestConfig &cfg, std::uint16_t port_override = 0) {
    ::tc8::stimulus::MethodRequestDestination dest{};
    if (cfg.someip.dut_iface_ip != 0) {
        dest.ipv4_be = cfg.someip.dut_iface_ip;
    }
    if (port_override != 0) {
        dest.port = port_override;
    } else if (cfg.someip.tcp_port != 0) {
        dest.port = cfg.someip.tcp_port;
    }
    return dest;
}

}  // namespace tc8::sce
