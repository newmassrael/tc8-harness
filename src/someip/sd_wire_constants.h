#pragma once

#include <cstdint>

namespace tc8 {

// SOME/IP-SD wire enumeration values (option Type, L4-Proto, entry Type),
// shared by the wire BUILDER (src/stimulus/someip_sd_builder.cpp) and the wire
// PARSER (src/someip/sd_decode.h) so a value is spelled exactly once across
// encode and decode. Neutral leaf owned by neither layer: it carries only the
// constants (no logic), so the encoder does not have to include the decoder to
// name an option type. Constants stay in namespace `tc8::sd_*` (not
// `tc8::someip::sd_*`) because the recognizer predicates and case headers —
// including out-of-tree OEM captured contexts — already reference them by that
// qualified name.

// Option Type values defined by SOMEIPSD §4.2.2 / SWS_SD §7.3 Table 11.
namespace sd_option_type {
inline constexpr std::uint8_t kConfiguration = 0x01;
inline constexpr std::uint8_t kLoadBalancing = 0x02;
inline constexpr std::uint8_t kIpv4Endpoint = 0x04;
inline constexpr std::uint8_t kIpv6Endpoint = 0x06;
inline constexpr std::uint8_t kIpv4Multicast = 0x14;
inline constexpr std::uint8_t kIpv6Multicast = 0x16;
inline constexpr std::uint8_t kIpv4SdEndpoint = 0x24;
inline constexpr std::uint8_t kIpv6SdEndpoint = 0x26;
}  // namespace sd_option_type

// Layer-4 Protocol values per IANA / SOMEIPSD endpoint options.
namespace sd_l4_proto {
inline constexpr std::uint8_t kTcp = 0x06;
inline constexpr std::uint8_t kUdp = 0x11;
}  // namespace sd_l4_proto

// SD entry Type byte (TR_SOMEIP / PRS_SOMEIPSD §7.4). The single source for the
// SD entry-type values: the recognizer predicates, the SD-fill gate, the wire
// builders, and the documentation-site summary (tc8-harness decode-pcap) all
// name these rather than re-spell the raw bytes. TTL (not a distinct type)
// discriminates the Stop* variants (Offer ttl==0 = StopOffer, Subscribe ttl==0
// = StopSubscribe).
namespace sd_entry_type {
inline constexpr std::uint8_t kFindService = 0x00;
inline constexpr std::uint8_t kOfferService = 0x01;
inline constexpr std::uint8_t kSubscribeEventgroup = 0x06;
inline constexpr std::uint8_t kSubscribeEventgroupAck = 0x07;
}  // namespace sd_entry_type

// SD message header Flags byte bits (TR_SOMEIP §4.2.1) — the top two bits of byte 0
// of the SD payload. Reboot = bit 7, Unicast = bit 6; bits 5..0 are reserved. The
// wire builders and cases OR these instead of spelling 0x80 / 0xC0 / 0x40 raw: the
// canonical post-boot Offer/Find/Subscribe flags are `kReboot | kUnicast`, a Reboot=0
// stream is `kUnicast`, and a case exercising undefined flag bits ORs in the low
// reserved bits (e.g. `kReboot | kUnicast | 0x3F`).
namespace sd_flags {
inline constexpr std::uint8_t kReboot  = 0x80;
inline constexpr std::uint8_t kUnicast = 0x40;
}  // namespace sd_flags

}  // namespace tc8
