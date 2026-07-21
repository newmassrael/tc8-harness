#pragma once

#include <cstdint>

namespace tc8::sce::dhcpv4 {

// TC8 §4.7 tester-side DHCP server emulation defaults — single source
// of truth shared by the server stimulus builder and the SCXML expect
// surface (`Dhcpv4Expected`). The §4.7.6.3 ALLOCATING_03 (Option 54
// echo) and §4.7.6.8 REQUEST_02 (Option 50 = OFFER yiaddr) lifecycle
// cases compare a captured REQUEST option against these constants.
//
// Encoded per the codebase `*_be == NBO bytes in memory` convention
// (cf. `ipv4_linklocal_common.h::kArbitraryReservedLinkLocalIpBe`):
// each octet is OR'd into the byte position the NBO wire bytes occupy
// on a little-endian host. constexpr-friendly without pulling
// htonl().
//
// Defaults pinned inside the dev netns 172.16.0.0/24 subnet
// (router 172.16.0.1, DUT 172.16.0.2, tester 172.16.0.3) but distinct
// from the live tester veth IP so the server identity is observable
// as "this is the emulated server, not the tester's own veth address".
// When the harness reaches an OEM-lab topology where the server IP
// must come from the DUT's external DHCP-relay configuration, lift
// these into `TestConfig::dhcpv4` and thread through `applyTestConfig`.
inline constexpr std::uint32_t kDefaultServerIdBe =     // 172.16.0.10
    (static_cast<std::uint32_t>(172U) <<  0) |
    (static_cast<std::uint32_t>(16U)  <<  8) |
    (static_cast<std::uint32_t>(0U)   << 16) |
    (static_cast<std::uint32_t>(10U)  << 24);
// §4.7.6.1 SUMMARY_02 tester-side multi-server filter — the second
// server emul (matched-xid OFFER) carries this distinct identifier so
// the captured DHCPREQUEST's Option 54 disambiguates which server the
// DUT selected. RFC 2131 §4.3.2 SELECTING: the client MUST echo the
// chosen server's ID in the REQUEST.
inline constexpr std::uint32_t kSecondServerIdBe =      // 172.16.0.11
    (static_cast<std::uint32_t>(172U) <<  0) |
    (static_cast<std::uint32_t>(16U)  <<  8) |
    (static_cast<std::uint32_t>(0U)   << 16) |
    (static_cast<std::uint32_t>(11U)  << 24);
inline constexpr std::uint32_t kDefaultOfferedIpBe =    // 172.16.0.50
    (static_cast<std::uint32_t>(172U) <<  0) |
    (static_cast<std::uint32_t>(16U)  <<  8) |
    (static_cast<std::uint32_t>(0U)   << 16) |
    (static_cast<std::uint32_t>(50U)  << 24);
inline constexpr std::uint32_t kDefaultSubnetMaskBe =   // 255.255.255.0
    (static_cast<std::uint32_t>(255U) <<  0) |
    (static_cast<std::uint32_t>(255U) <<  8) |
    (static_cast<std::uint32_t>(255U) << 16) |
    (static_cast<std::uint32_t>(0U)   << 24);
inline constexpr std::uint32_t kDefaultLeaseTimeSeconds = 300U;

// §4.7.6.7 CM_05/_06 / TC8 spec parameter `<IP-UNUSED-ADDRESS>`:
// "IP Address which is of a different subnet than all the emulated
// servers and all other objects within the simulated topologies"
// (tc8_p221-p240.txt:372). The harness uses 192.168.99.42 — a
// different RFC 1918 subnet from the dev-netns 172.16.0.0/24, so the
// DUT cannot egress directly without applying the Router Option
// (Option 3) from the OFFER/ACK.
inline constexpr std::uint32_t kUnusedRoutedIpBe =       // 192.168.99.42
    (static_cast<std::uint32_t>(192U) <<  0) |
    (static_cast<std::uint32_t>(168U) <<  8) |
    (static_cast<std::uint32_t>(99U)  << 16) |
    (static_cast<std::uint32_t>(42U)  << 24);

}  // namespace tc8::sce::dhcpv4
