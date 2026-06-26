#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

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

}  // namespace tc8::stimulus
