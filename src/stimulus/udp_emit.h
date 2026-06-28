#pragma once

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

#include "stimulus/arp_builder.h"  // kEthBroadcast / sendRawEthernet

namespace tc8::stimulus {

// Transmit `datagram` (the UDP payload) as an IPv4 unicast from source port
// `src_port` to `dst_ip_be`:`dst_port`, bound to the IPv4 address of
// `iface_name` (so it leaves the intended leg of a veth pair rather than
// whatever the default route picks). The caller chooses the source port: some
// protocols require a datagram to originate from a fixed, well-known port rather
// than an ephemeral one. `dst_ip_be` is a 32-bit IPv4 address in network byte
// order.
//
// The socket is opened, used once, and closed (stimulus is one-shot). Returns 0
// on success, or a negative errno-derived sentinel on failure (logged to
// stderr): -1 socket, -2 interface has no IPv4 address, -6 sendto, -7 bind /
// SO_REUSEADDR.
int sendUdpUnicast(const std::vector<std::uint8_t> &datagram, std::string_view iface_name,
                   std::uint16_t src_port, std::uint32_t dst_ip_be, std::uint16_t dst_port);

// Multicast sibling of sendUdpUnicast: transmit from `src_port` to
// `mcast_group`:`mcast_port`, pinning egress to `iface_name` via IP_MULTICAST_IF.
// `ttl` is the multicast hop limit (default 1 = link-local, the common harness
// case; the mechanism lives here, the value is the caller's policy). Returns 0
// on success or a negative sentinel (the unicast set plus -3 IP_MULTICAST_IF, -4
// IP_MULTICAST_TTL, -5 malformed group address).
int sendUdpMulticast(const std::vector<std::uint8_t> &datagram, std::string_view iface_name,
                     std::uint16_t src_port, std::string_view mcast_group, std::uint16_t mcast_port,
                     std::uint8_t ttl = 1);

// Build a complete Ethernet-II + IPv4 + UDP frame carrying `payload` (the UDP
// payload / L7) FROM a chosen source IP `src_ip_be`:`src_port` TO
// `dst_ip_be`:`dst_port`, ready to inject via `sendRawEthernet`. Pure (no I/O),
// so the wire layout is unit-testable. The UDP checksum is computed over the
// `src_ip_be`/`dst_ip_be` pseudo-header, so the two layers stay consistent.
// `dst_mac` defaults to Ethernet broadcast (Linux dispatches an IPv4 frame by
// dst_ip on a veth/netns pair regardless of the L2 destination); a real DUT
// needs its own MAC here for PACKET_HOST dispatch. `src_mac` defaults to zero.
std::vector<std::uint8_t> buildUdpFromSourceIpFrame(
    const std::vector<std::uint8_t> &payload, std::uint32_t src_ip_be, std::uint16_t src_port,
    std::uint32_t dst_ip_be, std::uint16_t dst_port,
    const std::array<std::uint8_t, 6> &dst_mac = kEthBroadcast,
    const std::array<std::uint8_t, 6> &src_mac = {});

// Raw-injection sibling of sendUdpUnicast for cases that must control the
// SOURCE IP, not just the source port — e.g. driving the DUT from two distinct
// sender IPs so it discriminates clients by Sender IP. sendUdpUnicast binds a
// socket to the iface IP,
// so the kernel owns the source IP; this builds the full frame with
// `src_ip_be` as the IPv4 source (`buildUdpFromSourceIpFrame`) and injects it
// at L2 via `sendRawEthernet` (AF_PACKET, CAP_NET_RAW). The DUT can only return
// a Response to `src_ip_be` if it can ARP-resolve it, so pair this with a
// tester-side ARP responder armed for `src_ip_be`. Returns 0 on success or the
// negative `sendRawEthernet` sentinel.
int sendUdpFromSourceIp(const std::vector<std::uint8_t> &payload, std::string_view iface,
                        std::uint32_t src_ip_be, std::uint16_t src_port,
                        std::uint32_t dst_ip_be, std::uint16_t dst_port,
                        const std::array<std::uint8_t, 6> &dst_mac = kEthBroadcast,
                        const std::array<std::uint8_t, 6> &src_mac = {});

}  // namespace tc8::stimulus
