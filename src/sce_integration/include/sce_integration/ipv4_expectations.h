#pragma once

#include <cstdint>

namespace tc8 {

// Flat DTO for the expected values a TC8 §4.4 IPv4 header case compares
// observed fields against. Carries only the topology-pinned IPv4
// identity (tester + DUT iface IP), both supplied by the operator via
// `--expect ipv4.<key>=<value>` (see `cli/expect_parser.cpp`).
//
// No `expected_version` / `expected_ttl` knob: §4.4.4.4 VERSION and
// §4.4.4.3 TTL fix the DUT-side literal by spec (version = 4, TTL >= 1),
// so the SCXML guard references the literal directly. Adding a CLI
// override here would invent a drift surface the spec does not.
//
// Mirror of `Icmpv4Expectations` / `ArpExpectations`: lives in its own
// header so `test_config.h` can aggregate it without pulling in the
// full `Ipv4Expected` Named Context layout.
struct Ipv4Expectations {
    std::uint32_t tester_ip    = 0;  // network byte order
    std::uint32_t dut_iface_ip = 0;  // network byte order

    // §4.6.5.5 UDP_USER_INTERFACE_07/_08 caller-specified IP axis
    // expectations. Stimulus pins the axis literal to a constant in
    // `udp_pilot_common.h` (`kDutAliasIp4Be` / `kTesterAliasIp4Be`),
    // while these slots carry what the SCXML compares against —
    // separation lets `--negative ipv4.dut_alias_ip=10.99.99.99` and
    // `--negative ipv4.tester_alias_ip=10.99.99.99` flip ONLY the
    // SCXML expectation. The DUT still emits the correct alias under
    // a conformant firmware, the harness's expected diverges, and
    // the cond lands on `fail_wrong_*` — proving the strict-axis
    // assertion is load-bearing rather than vacuous.
    //
    // Default 0 is harmless: only UI_07 / UI_08 SCXML consume these
    // slots. The smoke-test harness pins them in
    // `IPV4_DUT_EXPECT_STATIC` so the positive run resolves to the
    // netns-configured alias literals.
    std::uint32_t dut_alias_ip    = 0;  // network byte order — UI_07
    std::uint32_t tester_alias_ip = 0;  // network byte order — UI_08
};

}  // namespace tc8
