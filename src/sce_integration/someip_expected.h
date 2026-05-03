#pragma once

#include <cstdint>

#include "someip_expectations.h"
#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying DUT-identity values supplied by the
// CLI via `--expect`. Matching SCXML declaration:
//   <sce:context id="expected" cpp:type="tc8::SomeIpExpected"
//                cpp:include="sce_integration/someip_expected.h"/>
//
// Cases whose Test Procedure compares captured entry fields against a
// configured SERVICE-ID-1 identity (FORMAT_14..18) read these from their
// SCXML guards, e.g.
//
//   cond="cpp:captured.sd_entries[0].service_id == expected.service_id"
//
// Default 0 is never a valid DUT identity for the SOME/IP §5.1 suite,
// so a case that lands here with expectations unset will fall into its
// fail_* sink — the failure reason plus the CLI banner lets the operator
// notice the missing configuration without another layer of validation
// plumbing.
//
// Cases that don't read expected values (FORMAT_01..13) still declare
// this context in their SCXML so the SCE codegen emits a uniform two-arg
// state-machine constructor; `TestRunner<SM>` always constructs both
// captured and expected unconditionally.
struct SomeIpExpected {
    std::uint16_t service_id = 0;
    std::uint16_t instance_id = 0;
    std::uint8_t major_version = 0;
    std::uint32_t ttl = 0;
    std::uint32_t minor_version = 0;
    // Type 2 entry field — SubscribeEventgroup / Ack entries carry this
    // instead of minor_version. Used by FORMAT_28.
    std::uint16_t eventgroup_id = 0;

    // §5.1.5.5 OPTIONS endpoint values. See `SomeIpExpectations` doc-
    // comment in `someip_expectations.h` for semantics.
    std::uint32_t dut_iface_ip = 0;
    std::uint16_t udp_port = 0;
    std::uint16_t tcp_port = 0;

    // SD multicast destination address (NBO). Compared against
    // `SomeIpCaptured::dst_ip` by §5.1.5.4 SD_BEHAVIOR_03/_04 to
    // verify the DUT answers FindService with a multicast OfferService.
    std::uint32_t sd_multicast_ip = 0;

    // Multicast eventgroup endpoint values consumed by §5.1.5.5
    // OPTIONS_11 (IPv4) and OPTIONS_14 (port). See `SomeIpExpectations`
    // doc-comment in `someip_expectations.h` for byte-order semantics.
    std::uint32_t mcast_ipv4 = 0;
    std::uint16_t mcast_port = 0;
};

// ADL hook called by `TestRunner<SM>` at construction for any case whose
// expected-context Named Context is `SomeIpExpected`. Copies the flat DTO
// fields supplied via CLI `--expect`. Adding a new Named Context type
// means adding a matching overload in its own header; missing overloads
// fail at compile time rather than silently skipping configuration.
inline void applyTestConfig(SomeIpExpected &e, const TestConfig &cfg) {
    e.service_id = cfg.someip.service_id;
    e.instance_id = cfg.someip.instance_id;
    e.major_version = cfg.someip.major_version;
    e.ttl = cfg.someip.ttl;
    e.minor_version = cfg.someip.minor_version;
    e.eventgroup_id = cfg.someip.eventgroup_id;
    e.dut_iface_ip = cfg.someip.dut_iface_ip;
    e.udp_port = cfg.someip.udp_port;
    e.tcp_port = cfg.someip.tcp_port;
    e.sd_multicast_ip = cfg.someip.sd_multicast_ip;
    e.mcast_ipv4 = cfg.someip.mcast_ipv4;
    e.mcast_port = cfg.someip.mcast_port;
}

}  // namespace tc8
