#pragma once

#include <array>
#include <cstdint>

#include "tc8/protocol_frames/dot1q_tag.h"

namespace tc8 {

// DHCP UDP envelope ports (RFC 2131): server 67, client 68. Single source for
// the port-pair recognizer shared by the dissect pipeline's Dhcpv4Frame gate,
// the documentation-site exporter, the DHCP frame builder, and the BPF filter
// strings — so "which ports are DHCP" is spelled once. Top-level in tc8 (like
// kDot1QTpid) to avoid an enclosing-namespace binding trap; callers qualify
// ::tc8::kDhcpServerPort / ::tc8::isDhcpPortPair.
inline constexpr std::uint16_t kDhcpServerPort = 67;
inline constexpr std::uint16_t kDhcpClientPort = 68;
inline constexpr bool isDhcpPortPair(std::uint16_t src_port, std::uint16_t dst_port) {
    return src_port == kDhcpServerPort || dst_port == kDhcpServerPort ||
           src_port == kDhcpClientPort || dst_port == kDhcpClientPort;
}

// RFC 2131 DHCPv4 BOOTP header plus Option 53 (DHCP Message Type)
// pulled out for convenience — §4.7 test cases routinely switch on the
// exchange phase (DISCOVER / OFFER / REQUEST / ACK / NAK / DECLINE /
// RELEASE / INFORM). Additional options are exposed as a raw byte range
// so per-case dispatch can parse what it needs without expanding this
// struct for every option code.
//
// L2/L3/L4 envelope fields (eth_*, src_ip, dst_ip, src/dst_port, ip_*)
// mirror `UdpFrame` so a §4.7 case can express both "the BOOTP body
// shape" (yiaddr / chaddr / options) and "the carrying-frame shape"
// (DUT MAC source, IP source-zero invariant for DHCPDISCOVER) without
// hopping between two captured contexts.
struct Dhcpv4Frame {
    // Encapsulating Ethernet header. Source = DUT MAC for DUT-emitted
    // requests; destination = ff:ff:ff:ff:ff:ff for DISCOVER/REQUEST
    // pre-binding (RFC 2131 §4.1).
    std::array<std::uint8_t, 6> eth_src{};
    std::array<std::uint8_t, 6> eth_dst{};

    // IPv4 envelope (network byte order). DHCPDISCOVER has src_ip = 0
    // (CONSTRUCTING_MESSAGES_03) and dst_ip = 255.255.255.255.
    std::uint32_t src_ip = 0;
    std::uint32_t dst_ip = 0;
    std::uint8_t  ip_flags = 0;
    std::uint16_t ip_fragment_offset = 0;

    // UDP envelope. Server bind = 67, client bind = 68.
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;

    // BOOTP fixed header (RFC 951 / RFC 2131 §2).
    std::uint8_t  op    = 0;   // 1 = BOOTREQUEST, 2 = BOOTREPLY
    std::uint8_t  htype = 0;   // 1 = Ethernet
    std::uint8_t  hlen  = 0;   // 6 for Ethernet
    std::uint8_t  hops  = 0;
    std::uint32_t xid   = 0;
    std::uint16_t secs  = 0;
    std::uint16_t flags = 0;   // RFC 2131 §2: bit 0 = BROADCAST, bits 1..15 reserved (MUST be 0)
    std::uint32_t ciaddr = 0;
    std::uint32_t yiaddr = 0;
    std::uint32_t siaddr = 0;
    std::uint32_t giaddr = 0;
    std::array<std::uint8_t, 16> chaddr{};

    // True iff bytes 236..239 of the BOOTP body match RFC 1497 / RFC 2131
    // magic cookie 0x63 0x82 0x53 0x63. PROTOCOL_01's pass criterion;
    // also the gating predicate the pipeline uses to distinguish a DHCP
    // datagram from a non-DHCP UDP packet on port 67/68.
    bool magic_cookie_valid = false;

    // Option 53 (DHCP Message Type): 1 DISCOVER, 2 OFFER, 3 REQUEST,
    // 4 DECLINE, 5 ACK, 6 NAK, 7 RELEASE, 8 INFORM. 0 if the option
    // is absent (e.g. classic BOOTP exchange or malformed DHCP).
    std::uint8_t  message_type = 0;

    // Whether option 53 (Message Type) was present in the options blob.
    // PROTOCOL_02 / PROTOCOL_03 assert presence; the 0-value-as-absent
    // convention on `message_type` itself is ambiguous (DHCP message
    // types start at 1, but a malformed length-0 option could leave
    // the field zero) so a dedicated flag is the textbook predicate.
    bool message_type_option_present = false;

    // Whether the options blob (post magic cookie) terminates with the
    // 0xFF END marker. CONSTRUCTING_MESSAGES_01's pass criterion.
    // False when the blob is empty, terminates on something else, or
    // the magic cookie was missing (no options at all).
    bool last_option_is_end = false;

    // Raw options blob covering bytes 240..end of the BOOTP body
    // (i.e. everything AFTER the magic cookie, INCLUDING the trailing
    // END marker so per-case parsers can iterate over the full TLV
    // chain). Non-owning; valid only during dispatch.
    const std::uint8_t* options_data = nullptr;
    std::uint32_t       options_len  = 0;

    // Wall-clock arrival timestamp surface — same contract as
    // `UdpFrame::observed_ts_us`. Future REACQUISITION timing cases
    // and CONSTRUCTING_MESSAGES_12/_13 retransmission backoff cases
    // will read this via a `frame_delta_us()` helper on the Captured
    // context.
    std::int64_t observed_ts_us = 0;

    // IEEE 802.1Q tag, populated by the dissector when the carrying UDP
    // frame had one (inherited from the parent `UdpFrame::vlan`). OEM
    // VLAN profiles read this; no in-tree §4.7 case asserts on it.
    Dot1QTag vlan{};
};

}  // namespace tc8
