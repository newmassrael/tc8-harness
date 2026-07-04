#include "stimulus/someip_sd_builder.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstdio>
#include <string>
#include <thread>

#include "someip/protocol.h"  // tc8::someip::kSdServiceId / kSdMethodId (SD Message ID SSOT)
#include "someip/sd_wire_constants.h"  // sd_option_type / sd_l4_proto / sd_entry_type (wire values SSOT)
#include "someip/wire.h"
#include "stimulus/iface_addr.h"
#include "stimulus/udp_emit.h"
#include "tc8/dut_config.h"

namespace tc8::stimulus {

// The SOME/IP-SD port (30490) — single source of truth in tc8::dut. Pulled in
// unqualified so every SD emit binds the same source port without re-stamping
// the literal (tc8::dut::kSdPort warns that divergence silently breaks cases).
using tc8::dut::kSdPort;

// Big-endian appenders are the shared SOME/IP wire SSOT (someip/wire.h).
using someip::putBe16;
using someip::putBe24;
using someip::putBe32;

namespace {

// The 24-byte preamble shared by EVERY SOME/IP-SD builder: the 16-byte SOME/IP
// header (routed through the wire.h `appendHeader` SSOT) followed by the SD
// sub-header (Flags 1B | 24-bit Reserved) and the Length-of-Entries-Array (4B).
// For SD the Message ID is fixed (service 0xFFFF / method 0x8100, the latter
// overridable only by the ETS Method-ID-mutation case), with NOTIFICATION /
// E_OK; only `session_id`, `length`, `flags`, `reserved` and `entries_len` vary.
// This is the single source of truth for the preamble layout — the per-builder
// hand-rolled copies are gone, so a header-field change lands in one place.
void appendSdHeader(std::vector<std::uint8_t> &b, std::uint16_t session_id,
                    std::uint32_t length, std::uint8_t flags, std::uint32_t entries_len,
                    std::uint32_t reserved = 0, std::uint16_t method_id = someip::kSdMethodId) {
    someip::Header h;
    h.service_id = someip::kSdServiceId;
    h.method_id = method_id;
    h.length = length;
    h.client_id = 0x0000;
    h.session_id = session_id;
    h.protocol_version = 0x01;
    h.interface_version = 0x01;
    h.message_type = static_cast<std::uint8_t>(someip::MessageType::NOTIFICATION);
    h.return_code = static_cast<std::uint8_t>(someip::ReturnCode::E_OK);
    someip::appendHeader(b, h);

    // SD sub-header: Flags byte + 24-bit Reserved + Length-of-Entries-Array.
    b.push_back(flags);
    putBe24(b, reserved);
    putBe32(b, entries_len);
}

// SD entry option-count byte selecting exactly one option in the first run
// (#Opt1=1 | #Opt2=0), i.e. the entry references the option at options index 0.
// The single source for that nibble across the referenced Find / Offer /
// Subscribe builders.
inline constexpr std::uint8_t kEntryOptionRun1 = 0x10;

// Append one IPv4 (SD) Endpoint option to an SD Options Array: the fixed 12-byte
// wire shape Length(9) | Type | Reserved(Discardable=0) | IPv4 address (streamed
// MSB-first from the network-order uint32) | Reserved | L4-Proto | Port. Single
// encoder for the endpoint-option shape the Find / Offer / Subscribe builders
// emit; `option_type` is sd_option_type::kIpv4Endpoint (0x04) or kIpv4SdEndpoint
// (0x24), whose bodies are byte-identical apart from the type byte.
void appendIpv4EndpointOption(std::vector<std::uint8_t> &b, std::uint8_t option_type,
                             const Ipv4Endpoint &ep) {
    constexpr std::uint16_t kOptionBodyLen = 9;
    putBe16(b, kOptionBodyLen);
    b.push_back(option_type);
    b.push_back(0);  // Reserved (Discardable flag = 0)
    b.push_back(static_cast<std::uint8_t>((ep.ipv4_be >> 0) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((ep.ipv4_be >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((ep.ipv4_be >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((ep.ipv4_be >> 24) & 0xFF));
    b.push_back(0);  // Reserved
    b.push_back(ep.l4proto);
    putBe16(b, ep.port);
}

// Shared body for the two public FindService-with-one-option builders. Kept
// file-local (not a public overload) so the public API exposes two clearly named
// functions instead of a `(option_type, bool referenced)` footgun; the two
// controlled call sites below pass the type + reference explicitly.
std::vector<std::uint8_t> buildFindServiceWithOneOption(const FindServiceParams &p,
                                                        const Ipv4Endpoint &endpoint,
                                                        std::uint8_t option_type, bool referenced) {
    // 56 B = 16 (SOME/IP header) + 4 (flags+reserved) + 4 (entries_len)
    //      + 16 (entry) + 4 (options_len) + 12 (one IPv4 Endpoint option).
    // Length field = 56 - 8 (header bytes before request_id) = 48.
    constexpr std::uint32_t kLengthField = 48;
    constexpr std::uint32_t kEntriesLen = 16;
    constexpr std::uint32_t kOptionsLen = 12;

    std::vector<std::uint8_t> b;
    b.reserve(56);

    appendSdHeader(b, p.session_id, kLengthField, p.sd_flags, kEntriesLen, p.sd_reserved);

    // FindService entry — one option, referenced only when requested.
    b.push_back(sd_entry_type::kFindService);
    b.push_back(0);  // IndexFirstOptionRun (the option is at options index 0)
    b.push_back(0);  // IndexSecondOptionRun
    b.push_back(referenced ? kEntryOptionRun1 : std::uint8_t{0x00});
    putBe16(b, p.target.service_id);
    putBe16(b, p.target.instance_id);
    b.push_back(p.target.major_version);
    putBe24(b, p.target.ttl);
    putBe32(b, p.target.minor_version);

    putBe32(b, kOptionsLen);
    appendIpv4EndpointOption(b, option_type, endpoint);
    return b;
}

}  // namespace

std::vector<std::uint8_t> buildFindService(const FindServiceParams &p) {
    // SOME/IP-SD TR_SOMEIP §7.3 wire layout:
    //   [SOME/IP header 16B] [Flags 1B | Reserved 3B] [EntriesLen 4B]
    //   [Entry 16B] [OptionsLen 4B]
    //
    // Payload = 4 (flags/reserved) + 4 (entries_len) + 16 (one entry) + 4
    //         = 28 bytes.
    // SOME/IP length field counts bytes from Request ID onwards:
    //   8 (request_id + proto/iface/msgtype/retcode) + 28 (payload) = 36.
    constexpr std::uint32_t kLengthField = 36;
    constexpr std::uint32_t kEntriesLen = 16;
    constexpr std::uint32_t kOptionsLen = 0;
    constexpr std::uint8_t kEntryTypeFind = 0x00;

    std::vector<std::uint8_t> b;
    b.reserve(44);

    appendSdHeader(b, p.session_id, kLengthField, p.sd_flags, kEntriesLen, p.sd_reserved);

    // FindService entry (16B).
    b.push_back(kEntryTypeFind);
    b.push_back(0);  // IndexFirstOptionRun
    b.push_back(0);  // IndexSecondOptionRun
    b.push_back(0);  // #Opt1 (4b) | #Opt2 (4b)
    putBe16(b, p.target.service_id);
    putBe16(b, p.target.instance_id);
    b.push_back(p.target.major_version);
    putBe24(b, p.target.ttl);
    putBe32(b, p.target.minor_version);

    // Length of Options Array = 0 (no options).
    putBe32(b, kOptionsLen);

    return b;
}

std::vector<std::uint8_t> buildFindServiceWithOption(const FindServiceParams &p,
                                                     const Ipv4Endpoint &endpoint) {
    // Unreferenced (#Opt1=0) IPv4 Endpoint option — the ETS_118-style "ignore the
    // not-required option" cases: the option is physically present but the DUT
    // must ignore it and still answer with at least one OfferService.
    return buildFindServiceWithOneOption(p, endpoint, sd_option_type::kIpv4Endpoint,
                                         /*referenced=*/false);
}

std::vector<std::uint8_t> buildFindServiceWithReferencedSdEndpointOption(const FindServiceParams &p,
                                                                         const Ipv4Endpoint &endpoint) {
    // Referenced (#Opt1=1) Type-0x24 IPv4 SD Endpoint option: a DUT that honours
    // the referenced endpoint option answers the Find to `endpoint` (address /
    // L4-proto / port) rather than to the SD sender.
    return buildFindServiceWithOneOption(p, endpoint, sd_option_type::kIpv4SdEndpoint,
                                         /*referenced=*/true);
}

std::vector<std::uint8_t> buildOfferService(const OfferServiceTarget &t) {
    // Wire layout mirrors buildFindService — 16 B SOME/IP + 4 B SD flags/
    // reserved + 4 B EntriesLen=16 + 16 B Type-0x01 entry + 4 B OptionsLen=0
    // = 44 B. Length field counts from request_id forward = 8 + 28 = 36.
    constexpr std::uint32_t kLengthField  = 36;
    constexpr std::uint32_t kEntriesLen   = 16;
    constexpr std::uint32_t kOptionsLen   = 0;
    constexpr std::uint8_t  kEntryTypeOffer = 0x01;

    std::vector<std::uint8_t> b;
    b.reserve(44);

    // Reboot|Unicast flags; OEM SUBSCRIBE/SD_BEHAVIOR override the Reboot bit.
    appendSdHeader(b, t.session_id, kLengthField, t.sd_flags, kEntriesLen);

    b.push_back(kEntryTypeOffer);
    b.push_back(0);                 // IndexFirstOptionRun
    b.push_back(0);                 // IndexSecondOptionRun
    b.push_back(0);                 // #Opt1 (4b) | #Opt2 (4b)
    putBe16(b, t.service_id);
    putBe16(b, t.instance_id);
    b.push_back(t.major_version);
    putBe24(b, t.ttl);              // ttl == 0 -> StopOfferService per SD §4.2
    putBe32(b, t.minor_version);

    putBe32(b, kOptionsLen);

    return b;
}

int emitOfferServiceMulticast(std::string_view iface, const OfferServiceTarget &target,
                              std::chrono::milliseconds pre_emit_wait) {
    if (pre_emit_wait.count() > 0) {
        std::this_thread::sleep_for(pre_emit_wait);
    }
    return sendSdMulticast(buildOfferService(target), iface);
}

std::vector<std::uint8_t>
buildOfferServiceWithEndpoint(const OfferServiceWithEndpointTarget &t) {
    // Wire layout: 16 B SOME/IP + 4 B SD flags + 4 B EntriesLen + 16 B
    // Type 0x01 entry + 4 B OptionsLen + 12 B IPv4 Endpoint option = 56 B.
    // Length field = 8 + 4 + 4 + 16 + 4 + 12 = 48.
    constexpr std::uint32_t kLengthField     = 48;
    constexpr std::uint32_t kEntriesLen      = 16;
    constexpr std::uint32_t kOptionsLen      = 12;
    constexpr std::uint8_t  kEntryTypeOffer  = 0x01;

    std::vector<std::uint8_t> b;
    b.reserve(56);

    // Reboot|Unicast flags; OEM overrides the Reboot bit.
    appendSdHeader(b, t.service.session_id, kLengthField, t.service.sd_flags, kEntriesLen);

    // OfferService entry referencing 1 option in run 1.
    b.push_back(kEntryTypeOffer);
    b.push_back(0);                 // IndexFirstOptionRun
    b.push_back(0);                 // IndexSecondOptionRun
    b.push_back(kEntryOptionRun1);
    putBe16(b, t.service.service_id);
    putBe16(b, t.service.instance_id);
    b.push_back(t.service.major_version);
    putBe24(b, t.service.ttl);
    putBe32(b, t.service.minor_version);

    putBe32(b, kOptionsLen);

    // IPv4 Endpoint option (12 B) via the shared endpoint-option encoder.
    appendIpv4EndpointOption(b, sd_option_type::kIpv4Endpoint, t.endpoint);

    return b;
}

int emitOfferServiceMulticastWithEndpoint(std::string_view iface,
                                          const OfferServiceWithEndpointTarget &t,
                                          std::chrono::milliseconds pre_emit_wait) {
    if (pre_emit_wait.count() > 0) {
        std::this_thread::sleep_for(pre_emit_wait);
    }
    OfferServiceWithEndpointTarget filled = t;
    if (filled.endpoint.ipv4_be == 0) {
        filled.endpoint.ipv4_be = ipv4OfInterface(iface);
        if (filled.endpoint.ipv4_be == 0) {
            std::fprintf(stderr,
                         "stimulus: interface '%.*s' has no IPv4 — cannot fill "
                         "OfferService endpoint option\n",
                         static_cast<int>(iface.size()), iface.data());
            return -2;
        }
    }
    return sendSdMulticast(buildOfferServiceWithEndpoint(filled), iface);
}

int sendSdMulticast(const std::vector<std::uint8_t> &datagram, std::string_view iface_name,
                    std::string_view mcast_group, std::uint16_t mcast_port) {
    // vsomeip enforces "SD source port must equal the SD port" and silently
    // drops SD messages from ephemeral ports (`Ignored SD message from unknown
    // port`), so the source port is the SD port (= mcast_port). The generic
    // bind / IP_MULTICAST_IF / sendto mechanics live in sendUdpMulticast.
    return sendUdpMulticast(datagram, iface_name, /*src_port=*/mcast_port, mcast_group, mcast_port);
}

int sendSdMulticastFromSourceIp(const std::vector<std::uint8_t> &datagram, std::string_view iface,
                                std::uint32_t src_ip_be, const std::array<std::uint8_t, 6> &src_mac,
                                std::string_view mcast_group, std::uint16_t mcast_port) {
    in_addr group_addr{};
    if (::inet_pton(AF_INET, std::string(mcast_group).c_str(), &group_addr) != 1) {
        std::fprintf(stderr, "stimulus: sendSdMulticastFromSourceIp inet_pton('%.*s') failed\n",
                     static_cast<int>(mcast_group.size()), mcast_group.data());
        return -5;  // mirror sendUdpMulticast's malformed-group sentinel
    }
    const std::uint32_t group_be = group_addr.s_addr;
    // Ethernet dst = the RFC 1112 multicast MAC for the group (sendUdpFromSourceIp
    // defaults dst_mac to broadcast, which is wrong for a multicast Find). Source
    // port = SD port (= mcast_port) so vsomeip accepts the spoofed-source Find,
    // exactly as sendSdMulticast does.
    return sendUdpFromSourceIp(datagram, iface, src_ip_be, /*src_port=*/mcast_port, group_be,
                               mcast_port, ipv4MulticastMac(group_be), src_mac);
}

int sendSdUnicast(const std::vector<std::uint8_t> &datagram, std::string_view iface_name,
                  std::uint32_t dst_ip_be, std::uint16_t dst_port) {
    // Source port bound to the SD port so vsomeip's "SD source port must equal
    // SD port" check accepts the message (else it logs `Ignored SD message from
    // unknown port`). The generic emit mechanics live in sendUdpUnicast.
    return sendUdpUnicast(datagram, iface_name, /*src_port=*/kSdPort, dst_ip_be, dst_port);
}

int emitFindServiceBoot(std::string_view iface, const FindServiceTarget &target, const BootTiming &timing) {
    // SD §4.2.1: Reboot=1 stays set until Session ID wraps 0xFFFF -> 0x0000.
    // This helper only runs the pre-wrap boot window (session 0x0001 up to
    // timing.total_emits, always < 0xFFFF in practice), so Reboot stays 1
    // on every emit and the Unicast-only 0x40 flag value is intentionally
    // unused here.
    constexpr std::uint8_t kSdFlagsBoot = 0xC0;

    return runBootCadence(timing, [&](int i) {
        FindServiceParams p{};
        p.target = target;
        p.session_id = static_cast<std::uint16_t>(0x0001 + i);
        p.sd_flags = kSdFlagsBoot;
        return sendSdMulticast(buildFindService(p), iface);
    });
}

std::vector<std::uint8_t> buildSubscribeEventgroup(const SubscribeEventgroupParams &p) {
    // SOME/IP-SD TR_SOMEIP §7.3 + TR_SOMEIP §7.1.3 wire layout for a SubscribeEventgroup:
    //   [SOME/IP header 16B] [Flags 1B | Reserved 3B] [EntriesLen 4B]
    //   [Type 2 entry 16B]   [OptionsLen 4B] [IPv4 Endpoint option 12B]
    //
    // Type 2 entry (subscribe) byte layout:
    //   0: Type (0x06)
    //   1: Index First Option Run (0)
    //   2: Index Second Option Run (0)
    //   3: #Opt1 (4b) | #Opt2 (4b)   — 0x10 (one option in run 1)
    //   4..5: Service ID
    //   6..7: Instance ID
    //   8:    Major Version
    //   9..11: TTL (24-bit BE)
    //   12..13: Reserved (12b) | Counter (4b)
    //   14..15: Eventgroup ID
    //
    // IPv4 Endpoint option (TR_SOMEIP §7.4.3), 12B total:
    //   0..1: Length = 9 (BE, option body size not counting the length field itself)
    //   2:    Type = 0x04 (IPv4 Endpoint)
    //   3:    Reserved = 0
    //   4..7: IPv4 address (network byte order)
    //   8:    Reserved = 0
    //   9:    L4-Proto (0x11 UDP, 0x06 TCP)
    //   10..11: Port (BE)
    //
    // Payload = 4 + 4 + 16 + 4 + 12 = 40 bytes.
    // SOME/IP length field counts bytes from Request ID onwards:
    //   8 (request_id + proto/iface/msgtype/retcode) + 40 (payload) = 48.
    // The SD Method ID comes from the someip::kSdMethodId SSOT; the rest of the
    // header is emitted by appendSdHeader. ETS_178 overrides it via method_id_override.
    constexpr std::uint32_t kLengthFieldCanonical = 48;
    constexpr std::uint32_t kEntriesLenCanonical = 16;
    constexpr std::uint32_t kOptionsLenCanonical = 12;
    // Each extra option contributes (length 2B + type 1B + reserved 1B + body
    // bytes) to the Options Array. Sum once for downstream length math.
    std::uint32_t extra_options_total_bytes = 0;
    for (const auto& eo : p.extra_options) {
        extra_options_total_bytes += static_cast<std::uint32_t>(4 + eo.body.size());
    }
    const std::uint32_t length_field = p.length_override.value_or(
        kLengthFieldCanonical + extra_options_total_bytes);
    const std::uint32_t entries_len_field =
        p.entries_len_override == 0 ? kEntriesLenCanonical : p.entries_len_override;
    const std::uint32_t options_len_field = p.options_len_override.value_or(
        kOptionsLenCanonical + extra_options_total_bytes);
    constexpr std::uint8_t kEntryTypeSubscribe = 0x06;
    constexpr std::uint16_t kOptionBodyLenCanonical = 9;  // Length field value for IPv4 Endpoint.
    const std::uint16_t option_body_len_field =
        p.option_body_len_override.value_or(kOptionBodyLenCanonical);
    constexpr std::uint8_t kOptionTypeIpv4 = 0x04;
    const std::uint8_t option_reserved0 = p.option_reserved0_override.value_or(0);
    const std::uint8_t option_reserved1 = p.option_reserved1_override.value_or(0);
    const std::uint8_t option_type_field = p.option_type_override.value_or(kOptionTypeIpv4);
    const std::uint16_t method_id_field = p.method_id_override.value_or(someip::kSdMethodId);
    // Canonical #Opt1 nibble is 1 ("one option in run 1"); ETS_115 overrides
    // to a value >1 to assert "more option references than exist".
    constexpr std::uint8_t kNumOptionsFirstCanonical = 1;
    const std::uint8_t num_options_first =
        p.num_options_first_override.value_or(kNumOptionsFirstCanonical) & 0x0F;
    const std::uint8_t num_options_second =
        p.num_options_second_override.value_or(0) & 0x0F;
    const std::uint8_t entry_byte3 = static_cast<std::uint8_t>(
        (num_options_first << 4) | num_options_second);
    const std::uint8_t index_first  = p.index_first_options_override.value_or(0);
    const std::uint8_t index_second = p.index_second_options_override.value_or(0);
    // §5.1.6 SOMEIP_ETS_176 / _177: trailing payload after the Options
    // Array. When `extra_trailing_in_length` is true the bytes are counted
    // by the SOME/IP Length field (canonical 48 + N). When false the
    // length stays at 48 so the trailing bytes are present on-wire but
    // not counted (DUT must still Ack per PRS_SOMEIPSD_00153).
    const std::uint32_t length_with_trailing =
        p.extra_trailing_in_length
            ? static_cast<std::uint32_t>(length_field +
                                         p.extra_trailing_payload.size())
            : length_field;

    std::vector<std::uint8_t> b;
    b.reserve(56 + p.extra_trailing_payload.size());

    // Header preamble via the SD SSOT. ETS_178 drives method_id_field;
    // ETS_123/_124/_125 inject a malformed entries_len_field; the Reserved
    // field is canonically 0 here (FindService owns the reserved override).
    appendSdHeader(b, p.session_id, length_with_trailing, p.sd_flags, entries_len_field,
                   /*reserved=*/0, method_id_field);

    // SubscribeEventgroup entry (16B, Type 2).
    b.push_back(kEntryTypeSubscribe);
    b.push_back(index_first);   // IndexFirstOptionRun (canonical 0)
    b.push_back(index_second);  // IndexSecondOptionRun (canonical 0)
    b.push_back(entry_byte3);   // #Opt1 (canonical 1) | #Opt2 (canonical 0)
    putBe16(b, p.target.service_id);
    putBe16(b, p.target.instance_id);
    b.push_back(p.target.major_version);
    putBe24(b, p.target.ttl);
    // Reserved (12b) | Counter (4b) — counter is the low nibble of byte 13; the
    // 12 reserved bits (byte 12 + high nibble of byte 13) stay zero unless a case
    // overrides them to set an implementation-defined entry flag.
    const std::uint16_t entry_reserved = p.target.entry_reserved.value_or(0) & 0x0FFF;
    putBe16(b, static_cast<std::uint16_t>((entry_reserved << 4) |
                                          (p.target.counter & 0x0F)));
    putBe16(b, p.target.eventgroup_id);

    // Length of Options Array. Canonical 12 (one IPv4 Endpoint option);
    // ETS_134/_135/_138/_139 override via options_len_override.
    putBe32(b, options_len_field);

    // IPv4 Endpoint option (12B).
    putBe16(b, option_body_len_field);
    b.push_back(option_type_field);     // canonical 0x04 (IPv4 Endpoint); ETS_116/_174 flip
    b.push_back(option_reserved0);  // Reserved (canonical 0; _144 flips)
    // IPv4 address — `ipv4_be` is already in network byte order, stream
    // it MSB-first without additional host-to-network conversion. The
    // `& 0xFF` masks defeat narrowing warnings under `-Wconversion`.
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 0) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 24) & 0xFF));
    b.push_back(option_reserved1);  // Reserved (canonical 0; _144 flips)
    b.push_back(p.tester_endpoint.l4proto);
    putBe16(b, p.tester_endpoint.port);

    // §5.1.6 SOMEIP_ETS_117 / _175 extra options appended after the
    // canonical IPv4 Endpoint option. Wire layout: Length 2B BE +
    // Type 1B + Reserved 1B + body bytes.
    for (const auto& eo : p.extra_options) {
        putBe16(b, static_cast<std::uint16_t>(eo.body.size()));
        b.push_back(eo.type);
        b.push_back(eo.reserved);
        b.insert(b.end(), eo.body.begin(), eo.body.end());
    }

    // §5.1.6 SOMEIP_ETS_176 / _177 trailing payload (extra bytes after the
    // Options Array). Empty by default; populated only by cases that need
    // unused-data-after-options assertions.
    if (!p.extra_trailing_payload.empty()) {
        b.insert(b.end(), p.extra_trailing_payload.begin(),
                 p.extra_trailing_payload.end());
    }

    return b;
}

namespace {

// One SubscribeEventgroup emit. Subscribe is sent UNICAST to the DUT's
// SD endpoint per SD §4.2 (vsomeip drops multicast-addressed Subscribes
// silently). vsomeip additionally enforces SD source-port = SD port:
// packets arriving from an ephemeral source port are logged as "Ignored
// SD message from unknown port" and dropped, so the sending socket binds
// explicitly to the SD port (30490). The tester endpoint advertised in
// the option is the port the DUT should send its Ack to — kept as the
// SD port as well to mirror real-client behaviour; pcap on the tester
// iface captures the Ack regardless of whether anything is bound there.
int subscribeOnce(const SubscribeEventgroupTarget &target, std::uint8_t sd_flags, std::uint16_t session_id,
                  std::string_view iface, const SubscribeDestination &dest, std::uint8_t l4proto = 0x11) {
    // The tester's own IPv4 is advertised inside the Subscribe option (the DUT
    // replies to it), so resolve it for the payload before delegating the wire
    // send to sendUdpUnicast (which re-resolves it to bind the SD source port).
    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — "
                     "cannot advertise tester endpoint in subscribe option\n",
                     static_cast<int>(iface.size()), iface.data());
        return -2;
    }

    SubscribeEventgroupParams p{};
    p.target = target;
    p.tester_endpoint.ipv4_be = if_addr;  // already network byte order from ifaddrs.
    p.tester_endpoint.port = kSdPort;
    p.tester_endpoint.l4proto = l4proto;
    p.session_id = session_id;
    p.sd_flags = sd_flags;
    return sendUdpUnicast(buildSubscribeEventgroup(p), iface, /*src_port=*/kSdPort, dest.ipv4_be, dest.port);
}

}  // namespace

std::vector<std::uint8_t>
buildMultiSubscribeEventgroup(const MultiSubscribeEventgroupParams &p) {
    // Same wire layout as buildSubscribeEventgroup but the entries
    // array carries N Type 2 entries instead of 1. All entries share
    // one option run (run 0 → single IPv4 Endpoint option in run 1).
    constexpr std::uint8_t kEntryTypeSubscribe = 0x06;

    const std::uint32_t entries_len_actual =
        static_cast<std::uint32_t>(16 * p.entries.size());
    // §5.1.6 SOMEIP_ETS_114: caller-supplied entries_len_override (non-zero)
    // injects a value diverging from the actual entry-bytes count; default
    // (0) means "use the actual computed value".
    const std::uint32_t entries_len =
        p.entries_len_override == 0 ? entries_len_actual : p.entries_len_override;
    constexpr std::uint32_t kOptionsLen = 12;
    // SOME/IP Length field still counts the ACTUAL entries bytes (so the
    // wire layout is internally consistent: header reads X entries-bytes
    // even when EntriesLen field lies). The mismatch is the spec hook.
    const std::uint32_t length_field =
        8 + 4 + 4 + entries_len_actual + 4 + kOptionsLen;

    std::vector<std::uint8_t> b;
    b.reserve(16 + 4 + 4 + entries_len + 4 + kOptionsLen);

    // EntriesLen may be a deliberately-malformed ETS_114 value; the Length field
    // above still counts the ACTUAL entry bytes (the internal-consistency hook).
    appendSdHeader(b, p.session_id, length_field, p.sd_flags, entries_len);

    for (const auto &t : p.entries) {
        b.push_back(kEntryTypeSubscribe);
        b.push_back(0);     // IndexFirstOptionRun
        b.push_back(0);     // IndexSecondOptionRun
        b.push_back(kEntryOptionRun1);  // #Opt1=1 | #Opt2=0
        putBe16(b, t.service_id);
        putBe16(b, t.instance_id);
        b.push_back(t.major_version);
        putBe24(b, t.ttl);
        // Reserved (12b) | Counter (4b), same layout as the single builder.
        const std::uint16_t entry_reserved = t.entry_reserved.value_or(0) & 0x0FFF;
        putBe16(b, static_cast<std::uint16_t>((entry_reserved << 4) | (t.counter & 0x0F)));
        putBe16(b, t.eventgroup_id);
    }

    putBe32(b, kOptionsLen);

    // IPv4 Endpoint option (12 B) via the shared endpoint-option encoder.
    appendIpv4EndpointOption(b, sd_option_type::kIpv4Endpoint, p.tester_endpoint);

    return b;
}

int emitMultiSubscribeEventgroup(std::string_view iface,
                                 const std::vector<SubscribeEventgroupTarget> &entries,
                                 std::chrono::milliseconds pre_emit_wait,
                                 const SubscribeDestination &dest) {
    std::this_thread::sleep_for(pre_emit_wait);

    if (entries.empty()) {
        return 0;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — "
                     "cannot advertise tester endpoint in multi-subscribe option\n",
                     static_cast<int>(iface.size()), iface.data());
        return -2;
    }

    MultiSubscribeEventgroupParams p{};
    p.entries = entries;
    p.tester_endpoint.ipv4_be = if_addr;
    p.tester_endpoint.port = kSdPort;
    p.tester_endpoint.l4proto = 0x11;
    p.session_id = 0x0001;
    p.sd_flags = 0xC0;
    return sendUdpUnicast(buildMultiSubscribeEventgroup(p), iface, /*src_port=*/kSdPort, dest.ipv4_be,
                          dest.port);
}

int emitMultiSubscribeEventgroupRaw(std::string_view iface,
                                    MultiSubscribeEventgroupParams params,
                                    std::chrono::milliseconds pre_emit_wait,
                                    const SubscribeDestination &dest) {
    std::this_thread::sleep_for(pre_emit_wait);

    if (params.entries.empty()) {
        return 0;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — "
                     "cannot advertise tester endpoint in multi-subscribe-raw option\n",
                     static_cast<int>(iface.size()), iface.data());
        return -2;
    }

    // Honor a caller-supplied tester endpoint; otherwise advertise this iface.
    if (params.tester_endpoint.ipv4_be == 0) {
        params.tester_endpoint.ipv4_be = if_addr;
        params.tester_endpoint.port = kSdPort;
        if (params.tester_endpoint.l4proto == 0) {
            params.tester_endpoint.l4proto = 0x11;
        }
    }
    return sendUdpUnicast(buildMultiSubscribeEventgroup(params), iface, /*src_port=*/kSdPort, dest.ipv4_be,
                          dest.port);
}

int emitSubscribeEventgroupBoot(std::string_view iface, const SubscribeEventgroupTarget &target,
                                const BootTiming &timing, const SubscribeDestination &dest) {
    constexpr std::uint8_t kSdFlagsBoot = 0xC0;

    return runBootCadence(timing, [&](int i) {
        return subscribeOnce(target, kSdFlagsBoot,
                             static_cast<std::uint16_t>(0x0001 + i), iface, dest);
    });
}

int emitSubscribeEventgroupBootTcpOption(std::string_view iface, const SubscribeEventgroupTarget &target,
                                         const BootTiming &timing, const SubscribeDestination &dest) {
    constexpr std::uint8_t kSdFlagsBoot = 0xC0;
    constexpr std::uint8_t kL4ProtoTcp = 0x06;

    return runBootCadence(timing, [&](int i) {
        return subscribeOnce(target, kSdFlagsBoot,
                             static_cast<std::uint16_t>(0x0001 + i), iface, dest,
                             kL4ProtoTcp);
    });
}

int emitSubscribeEventgroupOnce(std::string_view iface,
                                const SubscribeEventgroupTarget &target,
                                std::uint16_t session_id, std::uint8_t sd_flags,
                                std::uint8_t l4proto, const SubscribeDestination &dest) {
    return subscribeOnce(target, sd_flags, session_id, iface, dest, l4proto);
}

std::vector<std::uint8_t> buildSubscribeEventgroupAck(const SubscribeEventgroupAckParams &p) {
    // SOME/IP-SD entry type 0x07 (SubscribeEventgroupAck/Nack). The Type 2 entry
    // shape matches the SubscribeEventgroup; TTL > 0 = Ack, TTL == 0 = Nack.
    // Without a multicast endpoint the answer references no options (28-byte SD
    // payload, Length 36); with one it references a single IPv4 Multicast option
    // (40-byte payload, Length 48) — the Ack analogue of buildOfferService vs
    // buildOfferServiceWithEndpoint.
    constexpr std::uint32_t kEntriesLen = 16;
    constexpr std::uint8_t kEntryTypeSubscribeAck = 0x07;
    constexpr std::uint16_t kOptionBodyLen = 9;  // IPv4 Multicast option body size.

    const bool has_option = p.target.multicast_endpoint.has_value();
    const std::uint32_t options_len = has_option ? 12u : 0u;
    // Length counts from Request ID onward: 8 + SD flags(4) + EntriesLen(4)
    // + entry(16) + OptionsLen(4) + option bytes.
    const std::uint32_t length_field = 8 + 4 + 4 + kEntriesLen + 4 + options_len;

    std::vector<std::uint8_t> b;
    b.reserve(16 + 4 + 4 + 16 + 4 + options_len);

    appendSdHeader(b, p.session_id, length_field, p.sd_flags, kEntriesLen);

    // SubscribeEventgroupAck entry (16B, Type 0x07).
    b.push_back(kEntryTypeSubscribeAck);
    b.push_back(0);  // IndexFirstOptionRun
    b.push_back(0);  // IndexSecondOptionRun
    b.push_back(has_option ? kEntryOptionRun1 : static_cast<std::uint8_t>(0));
    putBe16(b, p.target.service_id);
    putBe16(b, p.target.instance_id);
    b.push_back(p.target.major_version);
    putBe24(b, p.target.ttl);  // ttl == 0 -> Nack per SD entry type 0x07.
    // Reserved (12b) | Counter (4b), same layout as the SubscribeEventgroup entry.
    const std::uint16_t entry_reserved = p.target.entry_reserved.value_or(0) & 0x0FFF;
    putBe16(b, static_cast<std::uint16_t>((entry_reserved << 4) | (p.target.counter & 0x0F)));
    putBe16(b, p.target.eventgroup_id);

    putBe32(b, options_len);

    // IPv4 Multicast option (12B) — only when the eventgroup is delivered by
    // multicast; the address bytes stream MSB-first from `ipv4_be` (already
    // network byte order).
    if (has_option) {
        const Ipv4Endpoint &ep = *p.target.multicast_endpoint;
        putBe16(b, kOptionBodyLen);
        b.push_back(p.target.multicast_option_type);  // canonical 0x14 (IPv4 Multicast)
        b.push_back(0);  // Reserved
        b.push_back(static_cast<std::uint8_t>((ep.ipv4_be >> 0) & 0xFF));
        b.push_back(static_cast<std::uint8_t>((ep.ipv4_be >> 8) & 0xFF));
        b.push_back(static_cast<std::uint8_t>((ep.ipv4_be >> 16) & 0xFF));
        b.push_back(static_cast<std::uint8_t>((ep.ipv4_be >> 24) & 0xFF));
        b.push_back(0);  // Reserved
        b.push_back(ep.l4proto);
        putBe16(b, ep.port);
    }

    return b;
}

int emitSubscribeEventgroupAck(std::string_view iface, const SubscribeEventgroupAckParams &p,
                               const SubscribeDestination &client_sd_dest) {
    // Server answer: source port = SD port (the tester's server SD endpoint),
    // destination = the DUT client's SD endpoint. sendSdUnicast binds the SD
    // source port so the DUT accepts the message as valid SD.
    return sendSdUnicast(buildSubscribeEventgroupAck(p), iface, client_sd_dest.ipv4_be,
                         client_sd_dest.port);
}

std::vector<std::uint8_t> buildSubscribeEventgroupNack(SubscribeEventgroupAckParams p) {
    p.target.ttl = 0;  // TTL 0 makes the entry type 0x07 a Nack.
    return buildSubscribeEventgroupAck(p);
}

int emitSubscribeEventgroupRaw(std::string_view iface,
                               SubscribeEventgroupParams params,
                               const SubscribeDestination &dest,
                               std::uint32_t source_ip_be) {
    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — "
                     "cannot advertise tester endpoint in subscribe-raw option\n",
                     static_cast<int>(iface.size()), iface.data());
        return -2;
    }

    // Honor a caller-supplied tester endpoint; otherwise advertise this iface.
    if (params.tester_endpoint.ipv4_be == 0) {
        params.tester_endpoint.ipv4_be = if_addr;
        params.tester_endpoint.port = kSdPort;
        if (params.tester_endpoint.l4proto == 0) {
            params.tester_endpoint.l4proto = 0x11;
        }
    }
    return sendUdpUnicast(buildSubscribeEventgroup(params), iface, /*src_port=*/kSdPort, dest.ipv4_be,
                          dest.port, source_ip_be);
}

}  // namespace tc8::stimulus
