#pragma once

#include <array>
#include <cstdint>

namespace tc8 {

// The DUT's wire identity on the test link: the MAC and IPv4 address the
// tester emits frames *to*. This is a topology fact, not a per-protocol
// expectation — every protocol's stimulus path (ARP, IPv4, ICMPv4, UDP,
// TCP, DHCPv4, SOME/IP) needs the same DUT MAC as the Ethernet
// destination and the same DUT IP as the L3 destination, so it lives in
// one domain-neutral home (`TestConfig::dut`) rather than being sourced
// from any single protocol's struct.
//
// Distinct from the per-protocol `dut_iface_ip` / `dut_iface_mac`
// expectation fields: those are values an SCXML guard compares an
// observed DUT frame *against* (and `--negative` flips them to prove
// mismatch paths); these are the addresses the tester targets when it
// *builds* a frame, and are never guard-compared. Keeping the two apart
// is what lets a `--negative` iface-IP flip shift only the expectation
// without also redirecting the stimulus and silencing the DUT.
//
// `ip` is network byte order (matches inet_pton / captured-side
// encoding); `mac` holds the six bytes in over-the-wire order.
// Populated via `--expect dut.ip=<dotted>` / `--expect dut.mac=<hex>`.
struct DutIdentity {
    std::array<std::uint8_t, 6> mac{};
    std::uint32_t ip = 0;
    // A SECOND address the DUT answers on, network byte order, or 0 for a DUT
    // that has only `ip`. A topology fact like the two above and populated the
    // same way (`--expect dut.secondary_ip=<dotted>`), declared by the topology
    // that provisions the alias rather than compiled into the case that needs it.
    //
    // It exists because a case can REQUIRE it: §4.6.5.5 UDP_USER_INTERFACE_07
    // proves the DUT honours a caller-specified source address, which needs the
    // DUT to HAVE a second one. The netns topologies alias 172.16.0.5 onto the
    // DUT veth; the lwIP fixture runs one netif with one address and cannot.
    // Leaving that premise compiled into the case made the fixture report a
    // standing non-conclusion instead of an honest skip (docs/tech-debt.md TD-25).
    //
    // ⚠ Deliberately NOT `ipv4.dut_alias_ip`, which looks like the same value and
    // is not: that one is an EXPECTATION a `--negative` row flips to prove the
    // guard is load-bearing. Deriving a capability from a field a negative row
    // rewrites would let a row silently change which cases run.
    std::uint32_t secondary_ip = 0;
};

}  // namespace tc8
