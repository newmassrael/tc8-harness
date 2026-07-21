#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "stimulus/arp_builder.h"  // kEthBroadcast / kEthZero

namespace tc8::stimulus {

// TC8 §4.7 tester-side DHCP server emulation wire builder.
//
// `Dhcpv4ReplySpec` parameterises a single BOOTREPLY datagram (DHCPOFFER
// when `message_type == 2`, DHCPACK when `message_type == 5`, DHCPNAK
// when `message_type == 6`). The harness server emul does not maintain
// per-client lease state — every reply is constructed fresh from the
// captured request's xid + chaddr — so the builder is a pure function
// of `spec`. Lifecycle cases that need to forge mismatched-xid OFFERs
// (SUMMARY_02) populate `xid_be` with the desired off-by-one value.
//
// Wire layout (RFC 2131 §2 / RFC 1497):
//   14 B Ethernet (eth_dst broadcast — RFC 2131 §4.1: server response to
//                  client without ciaddr broadcasts; eth_src = tester MAC).
//   20 B IPv4    (src = server_id_be, dst = 255.255.255.255).
//   8 B  UDP     (src 67, dst 68).
//   240 B BOOTP fixed (op=2, htype=1, hlen=6, xid, chaddr, magic).
//   N B DHCP options (Option 53 msg_type, Option 54 server_id,
//                     Option 51 lease_time, Option 1 subnet_mask
//                     [optional], 0xFF END).
struct Dhcpv4ReplySpec {
    // L2 / L3 envelope.
    std::array<std::uint8_t, 6> eth_dst    = kEthBroadcast;
    std::array<std::uint8_t, 6> eth_src    = kTesterInjectedMac;
    std::uint32_t               src_ip_be  = 0;   // = server_id_be by convention
    std::uint32_t               dst_ip_be  = 0xFFFFFFFFU;

    // BOOTP fixed body. xid + chaddr come from the captured request.
    // `xid` is host-order (matches `Dhcpv4Captured::xid`, which the
    // pipeline reconstructs from BE wire bytes via shift-OR); the
    // builder writes it back out big-endian.
    std::uint32_t                  xid      = 0;
    std::array<std::uint8_t, 6>    chaddr   {};

    // DHCP Option 53 (Message Type): 2 OFFER, 5 ACK, 6 NAK.
    std::uint8_t  message_type = 2;

    // BOOTP yiaddr — the offered/acknowledged IPv4 address. NBO.
    std::uint32_t yiaddr_be = 0;

    // DHCP Option 54 (Server Identifier). NBO.
    std::uint32_t server_id_be = 0;

    // DHCP Option 51 (IP Address Lease Time) in seconds. Set 0 to omit
    // the option entirely. The builder also force-omits Option 51 on
    // DHCPNAK (message_type == 6) per RFC 2131 §4.3.2 — callers can
    // pass a generic `ServerEmulParams` without zeroing this field.
    // Most non-NAK cases want a positive value.
    std::uint32_t lease_time_seconds = 0;

    // DHCP Option 1 (Subnet Mask). NBO. 0 omits the option. The
    // builder also force-omits Option 1 on DHCPNAK per RFC 2131 §4.3.2.
    // Most lifecycle cases don't assert against the mask, but emitting
    // the commonly-expected /24 makes the DUT's REQUEST flow more
    // realistic (some clients refuse to bind without a mask).
    std::uint32_t subnet_mask_be = 0;

    // §4.7.6.1 SUMMARY_03 / RFC 2131 §2 maximum DHCP message size.
    // When non-zero, the builder appends RFC 2131 §3 PAD options
    // (0x00) before the END marker so the IPv4 datagram total length
    // (header + UDP + BOOTP + options) reaches `ip_datagram_total_bytes`.
    // Used by SUMMARY_03 to verify the DUT can ingest a 576-byte OFFER
    // (the RFC 791 minimum reassembly size, also the RFC 2131 §2
    // maximum DHCP message size). 0 = no padding (default).
    std::uint16_t ip_datagram_total_bytes = 0;

    // §4.7.6.7 CM_05/_06 / RFC 2132 §9.3 Option Overload. Drives
    // builder logic that:
    //   * Emits Option 52 (Overload) in the main options blob with
    //     `option_52_overload` as the value (1 = file holds options,
    //     2 = sname holds options, 3 = both).
    //   * Copies `sname_payload` into the BOOTP fixed `sname` field
    //     (offset 44, 64 B); excess bytes are clamped, missing bytes
    //     stay zero (RFC 2131 §2 default).
    //   * Copies `file_payload` into the BOOTP fixed `file` field
    //     (offset 108, 128 B); same clamping rules.
    //
    // Builder ordering — caller is responsible for terminating each
    // payload with the END marker (0xFF) per RFC 2132 §9.3 ("the
    // last valid option in the file/sname overloaded field MUST be
    // the END option (255)"). The builder does NOT auto-append END
    // because the caller may construct multi-option payloads whose
    // END placement is part of the spec-asserted shape.
    //
    // 0 / empty defaults preserve pre-S11 behaviour: every existing
    // case ignores these fields and the builder emits zero-filled
    // sname/file regions with no Option 52 in the main options.
    std::uint8_t                option_52_overload = 0;
    std::vector<std::uint8_t>   sname_payload;
    std::vector<std::uint8_t>   file_payload;
};

// Build a 14 + 20 + 8 + 240 + opts byte BOOTREPLY frame from `spec`.
// Callers feed the result to `sendRawEthernet`.
std::vector<std::uint8_t> buildDhcpv4Reply(const Dhcpv4ReplySpec& spec);

}  // namespace tc8::stimulus
