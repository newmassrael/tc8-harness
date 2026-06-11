#pragma once

#include <array>
#include <cstdint>

namespace tc8 {

// Flat DTO for the expected values a TC8 §4.2 ARP case compares observed
// ARP / cross-protocol frame fields against, supplied via
// `--expect arp.<key>=<value>` (see `cli/expect_parser.cpp`). Every field
// here is guard-compared by some SCXML cond — that is the type's single
// responsibility. The DUT's wire identity (the address frames are sent
// *to*, never compared) lives in `DutIdentity` (`TestConfig::dut`); ARP
// stimulus knobs that steer the case rather than gate its verdict live in
// `ArpStimulusConfig` (`TestConfig::arp_stimulus`).
//
// Lives in its own header (rather than inside `arp_expected.h`) so
// `test_config.h` can aggregate it without pulling in the full
// `ArpExpected` Named Context layout, mirroring the `SomeIpExpectations`
// split. ADL-dispatched helpers on the Named Context types include
// `test_config.h` without a cycle.
//
// IPv4 fields hold the address in network byte order — same encoding as
// `inet_pton(AF_INET, ...)` and as the captured-side `ArpFrame::*_proto_ip`
// fields, so SCXML guards compare without a swap. MAC fields hold the six
// bytes in over-the-wire order.
struct ArpExpectations {
    std::array<std::uint8_t, 6> dut_iface_mac{};
    std::uint32_t dut_iface_ip = 0;
    std::uint32_t tester_ip = 0;
    // MAC the tester injects as sender-HW into the §4.2.4.1 ARP Learning
    // stimulus (hardcoded to `kTesterInjectedMac` in `arp_builder.h`; the
    // CLI value is purely an *expectation* the SCXML guards compare
    // captured UDP Eth-dst against). Smoke-test sets this to the same
    // literal; `--negative` overrides to prove SCXML mismatch paths.
    std::array<std::uint8_t, 6> tester_mac{};
    // Second tester MAC used by §4.2.4.2 Phase 3b Group C cache-merge
    // cases (ARP_32/33/34/35). Same hardcoded-in-stimulus / expected-via-
    // CLI split as `tester_mac`; the stimulus reads `kTesterInjectedMac2`
    // from `arp_builder.h`, the SCXML compares captured UDP eth_dst
    // against this expectation.
    std::array<std::uint8_t, 6> tester_mac2{};
    // Third tester MAC used by §4.2.4.2 Phase 3c Group D case ARP_40 —
    // the spec injects an ARP Response with `sender_hw = MAC-ADDR3`,
    // and the DUT's subsequent UDP egress `eth_dst` is verified against
    // this expectation. Stimulus reads `kTesterInjectedMac3`; SCXML
    // compares.
    std::array<std::uint8_t, 6> tester_mac3{};
    // §4.5.6.2 ADDRESS_SELECTION_16 (RFC 3927 §2.5 claim-condition):
    // tester-side LL address used as `sender_proto_ip` of the
    // who-has Request injected after the DUT's claim. NBO; default
    // 169.254.1.2 (wire bytes A9 FE 01 02 → LE uint32 0x0201FEA9).
    // RFC 3927 §2.5 doesn't pin the asker; the default is a single
    // valid value for the dev-netns topology. Override via
    // `--expect arp.tester_linklocal_ip=...` for OEM lab topologies
    // whose tester is on a different LL.
    std::uint32_t tester_linklocal_ip = 0x0201FEA9U;
};

}  // namespace tc8
