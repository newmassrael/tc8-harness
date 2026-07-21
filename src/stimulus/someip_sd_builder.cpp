#include "stimulus/someip_sd_builder.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cassert>
#include <cstdio>
#include <string>
#include <thread>
#include <utility>

#include "tc8/someip/protocol.h"  // tc8::someip::kSdServiceId / kSdMethodId (SD Message ID SSOT)
#include "tc8/someip/sd_wire_constants.h"  // sd_option_type / sd_l4_proto / sd_entry_type (wire values SSOT)
#include "tc8/someip/wire.h"
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

// The #Opt1/#Opt2 option-run count byte of an SD entry (byte 3): #Opt1 in the high
// nibble, #Opt2 in the low. Single source for the option-run packing shared by the
// Type-1 (Find/Offer) and Type-2 (Subscribe/Ack) entry builders.
constexpr std::uint8_t sdEntryOptionRun(std::uint8_t num_first, std::uint8_t num_second = 0) {
    return static_cast<std::uint8_t>(((num_first & 0x0F) << 4) | (num_second & 0x0F));
}

// #Opt1=1 | #Opt2=0 — the entry references exactly one option at options index 0.
// The single source for that nibble across the referenced Find / Offer / Subscribe
// builders.
inline constexpr std::uint8_t kEntryOptionRun1 = sdEntryOptionRun(1);

// #Opt1=2 | #Opt2=0 — the entry references two contiguous options (index 0 and 1);
// used by an Offer that references both a data endpoint and a Configuration option.
inline constexpr std::uint8_t kEntryTwoOptionsRun1 = sdEntryOptionRun(2);

// The SOME/IP Length field of an SD message: the 8 bytes counted from Request ID
// (request id + proto/iface/msgtype/retcode) plus the SD framing — 4 (flags/reserved)
// + 4 (EntriesLen field) + entries_bytes + 4 (OptionsLen field) + options_bytes.
// Single source for every SD builder's Length arithmetic (was a per-builder 36/48/60).
constexpr std::uint32_t sdSomeIpLengthField(std::uint32_t entries_bytes,
                                            std::uint32_t options_bytes) {
    return 20u + entries_bytes + options_bytes;
}

// Append one IPv4 (SD) Endpoint option to an SD Options Array: the fixed 12-byte
// wire shape Length(9) | Type | Reserved(Discardable=0) | IPv4 address (streamed
// MSB-first from the network-order uint32) | Reserved | L4-Proto | Port. Single
// encoder for the endpoint-option shape the Find / Offer / Subscribe builders
// emit; `option_type` is sd_option_type::kIpv4Endpoint (0x04) or kIpv4SdEndpoint
// (0x24), whose bodies are byte-identical apart from the type byte.
void appendIpv4EndpointOption(std::vector<std::uint8_t> &b, std::uint8_t option_type,
                             const Ipv4Endpoint &ep) {
    // Body (address + reserved + L4-proto + port) via the public sdIpv4OptionBody SSOT.
    // Length counts the bytes after the Type byte: Reserved(1) + body(8) = 9.
    const std::vector<std::uint8_t> body = sdIpv4OptionBody(ep);
    putBe16(b, static_cast<std::uint16_t>(1u + body.size()));
    b.push_back(option_type);
    b.push_back(0);  // Reserved (Discardable flag = 0)
    b.insert(b.end(), body.begin(), body.end());
}

// Append one SOME/IP-SD Configuration option (Type 0x01) to an SD Options Array:
// Length(2B BE) | Type(0x01) | Reserved(0) | config string (via the
// `encodeSdConfigOptionBody` SSOT). The Length field counts everything after the Type
// byte — Reserved(1) + config string — matching `appendIpv4EndpointOption`'s
// convention and the `sd_decode.h` Configuration-option reader.
void appendConfigurationOption(std::vector<std::uint8_t> &b,
                              const std::vector<std::pair<std::string, std::string>> &items) {
    const std::vector<std::uint8_t> cs = encodeSdConfigOptionBody(items);
    const std::size_t opt_len = 1u + cs.size();  // Reserved(1) + config string.
    assert(opt_len <= 0xFFFFu && "SD Configuration option exceeds the 16-bit Length");
    putBe16(b, static_cast<std::uint16_t>(opt_len));
    b.push_back(sd_option_type::kConfiguration);
    b.push_back(0);  // Reserved (Discardable flag = 0)
    b.insert(b.end(), cs.begin(), cs.end());
}

// Append one caller-supplied extra SD option to an Options Array — the entry-referenced
// extras of an Offer and the trailing extras of a Subscribe. Wire shape:
// Length(2B BE) | Type(1B) | Reserved(1B) | body. The Length field counts everything
// after the Type byte — Reserved(1) + body — matching appendIpv4EndpointOption /
// appendConfigurationOption and the sd_decode.h option walk (opt_total = 3 + Length).
// The single source for the extra-option append shared by the Offer and Subscribe builders.
void appendSdExtraOption(std::vector<std::uint8_t> &b, const SdExtraOption &eo) {
    const std::size_t opt_len = 1u + eo.body.size();  // Reserved(1) + body.
    assert(opt_len <= 0xFFFFu && "SD extra option exceeds the 16-bit Length");
    putBe16(b, static_cast<std::uint16_t>(opt_len));
    b.push_back(eo.type);
    b.push_back(eo.reserved);
    b.insert(b.end(), eo.body.begin(), eo.body.end());
}

// Append one SOME/IP-SD Type-1 entry (FindService / OfferService, TR_SOMEIP §7.4
// Type 1 format): EntryType | IndexFirstOptionRun | IndexSecondOptionRun |
// #Opt1|#Opt2 | ServiceID | InstanceID | MajorVersion | TTL(24b) | MinorVersion.
// The single source of the Type-1 entry wire shape — the entry-level parallel of
// appendSdHeader (preamble SSOT) and appendIpv4EndpointOption (option SSOT), shared
// by every Find/Offer builder. IndexFirstOptionRun is a parameter — a case may start
// the entry's option run at a non-zero options index (e.g. an Offer whose data
// endpoint follows an SD Endpoint option at index 0). IndexSecondOptionRun stays 0:
// no Type-1 case needs a second option run yet (add a param the day one does).
// `option_run` is 0 (no option referenced) or kEntryOptionRun1 (#Opt1=1); a 0 TTL
// makes an Offer a StopOffer (SD §4.2). Type-2 entries (Subscribe/Ack) carry a
// Counter/EventgroupID tail instead of MinorVersion, so they keep their own layout.
void appendSdType1Entry(std::vector<std::uint8_t> &b, std::uint8_t entry_type,
                        std::uint8_t index_first_run, std::uint8_t option_run,
                        std::uint16_t service_id, std::uint16_t instance_id,
                        std::uint8_t major_version, std::uint32_t ttl,
                        std::uint32_t minor_version) {
    b.push_back(entry_type);
    b.push_back(index_first_run);  // IndexFirstOptionRun (option-run start index)
    b.push_back(0);                // IndexSecondOptionRun (no 2nd run yet)
    b.push_back(option_run);
    putBe16(b, service_id);
    putBe16(b, instance_id);
    b.push_back(major_version);
    putBe24(b, ttl);
    putBe32(b, minor_version);
}

// Wire fields of a SOME/IP-SD Type-2 entry (SubscribeEventgroup /
// SubscribeEventgroupAck-Nack, TR_SOMEIP §7.4 Type 2). This is the WIRE model —
// deliberately distinct from the test-intent SubscribeEventgroup*Target structs:
// it carries the on-wire option-run descriptor (index/#Opt bytes) the targets do
// not, and flattens their optional Reserved field. Populated by name at each call
// site (C++17 has no designated-init) so no positional argument can transpose.
struct SdType2EntryFields {
    std::uint8_t  entry_type;        // kSubscribeEventgroup / kSubscribeEventgroupAck
    std::uint8_t  index_first_run;   // IndexFirstOptionRun (canonical 0)
    std::uint8_t  index_second_run;  // IndexSecondOptionRun (canonical 0)
    std::uint8_t  option_run;        // byte 3: #Opt1(4b) | #Opt2(4b)
    std::uint16_t service_id;
    std::uint16_t instance_id;
    std::uint8_t  major_version;
    std::uint32_t ttl;               // 24-bit; 0 = StopSubscribe / Nack (SD §4.2)
    std::uint16_t entry_reserved;    // 12-bit Reserved (masked here); shares byte 12-13 word
    std::uint8_t  counter;           // 4-bit Counter (masked here)
    std::uint16_t eventgroup_id;
};

// Append one SOME/IP-SD Type-2 entry — the entry-level SSOT parallel to
// appendSdType1Entry, shared by the Subscribe / MultiSubscribe / Ack builders.
// Bytes 0-11 match a Type-1 entry; bytes 12-15 carry Reserved(12b)|Counter(4b)
// then EventgroupID instead of MinorVersion. The Reserved/Counter bit-packing —
// the one subtle, drift-prone step — lives ONLY here.
void appendSdType2Entry(std::vector<std::uint8_t> &b, const SdType2EntryFields &e) {
    b.push_back(e.entry_type);
    b.push_back(e.index_first_run);
    b.push_back(e.index_second_run);
    b.push_back(e.option_run);
    putBe16(b, e.service_id);
    putBe16(b, e.instance_id);
    b.push_back(e.major_version);
    putBe24(b, e.ttl);
    const std::uint16_t reserved = e.entry_reserved & 0x0FFF;
    putBe16(b, static_cast<std::uint16_t>((reserved << 4) | (e.counter & 0x0F)));
    putBe16(b, e.eventgroup_id);
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
    constexpr std::uint32_t kEntriesLen = 16;
    constexpr std::uint32_t kOptionsLen = 12;
    constexpr std::uint32_t kLengthField = sdSomeIpLengthField(kEntriesLen, kOptionsLen);

    std::vector<std::uint8_t> b;
    b.reserve(56);

    appendSdHeader(b, p.session_id, kLengthField, p.sd_flags, kEntriesLen, p.sd_reserved);

    // FindService entry — one option, referenced only when requested.
    appendSdType1Entry(b, sd_entry_type::kFindService, /*index_first_run=*/0,
                       referenced ? kEntryOptionRun1 : std::uint8_t{0x00},
                       p.target.service_id, p.target.instance_id,
                       p.target.major_version, p.target.ttl, p.target.minor_version);

    putBe32(b, kOptionsLen);
    appendIpv4EndpointOption(b, option_type, endpoint);
    return b;
}

}  // namespace

std::vector<std::uint8_t>
encodeSdConfigOptionBody(const std::vector<std::pair<std::string, std::string>> &items) {
    // Config string: length-prefixed "key=value" items, zero-length-terminated —
    // `[len1]key1=value1 [len2]key2=value2 ... 0x00`. Each length byte counts
    // `key + '=' + value`. This is the body an SD Configuration option (Type 0x01)
    // carries after its Reserved byte, and equally the `ExtraSdOption::body` a
    // Subscribe entry references — one source for the shape (WRITER side; the READER
    // is sd_decode.h, cross-checked by the builder round-trip test).
    std::vector<std::uint8_t> cs;
    for (const auto &kv : items) {
        const std::size_t item_len = kv.first.size() + 1u + kv.second.size();  // key '=' value
        assert(item_len <= 0xFFu && "SD config item length exceeds the 8-bit prefix");
        cs.push_back(static_cast<std::uint8_t>(item_len));
        cs.insert(cs.end(), kv.first.begin(), kv.first.end());
        cs.push_back('=');
        cs.insert(cs.end(), kv.second.begin(), kv.second.end());
    }
    cs.push_back(0x00);  // zero-length item terminates the sequence
    return cs;
}

std::vector<std::uint8_t> sdIpv4OptionBody(const Ipv4Endpoint &ep) {
    // The 8 bytes of an IPv4 Endpoint / Multicast / SD Endpoint option AFTER its
    // Reserved byte: IPv4 address (streamed LSB-first — `ipv4_be` is already network
    // byte order, so no host-to-network swap), Reserved(1), L4-Proto(1), Port(2 BE).
    // appendIpv4EndpointOption wraps this with Length(9) + Type + Reserved; an
    // SdExtraOption carrying it gets Length = 1 + 8 = 9 the same way. The `& 0xFF`
    // masks defeat narrowing warnings under -Wconversion.
    return {
        static_cast<std::uint8_t>((ep.ipv4_be >> 0) & 0xFF),
        static_cast<std::uint8_t>((ep.ipv4_be >> 8) & 0xFF),
        static_cast<std::uint8_t>((ep.ipv4_be >> 16) & 0xFF),
        static_cast<std::uint8_t>((ep.ipv4_be >> 24) & 0xFF),
        0x00,
        ep.l4proto,
        static_cast<std::uint8_t>((ep.port >> 8) & 0xFF),
        static_cast<std::uint8_t>(ep.port & 0xFF),
    };
}

std::vector<std::uint8_t> buildFindService(const FindServiceParams &p) {
    // SOME/IP-SD TR_SOMEIP §7.3 wire layout:
    //   [SOME/IP header 16B] [Flags 1B | Reserved 3B] [EntriesLen 4B]
    //   [Entry 16B] [OptionsLen 4B]
    //
    // Payload = 4 (flags/reserved) + 4 (entries_len) + 16 (one entry) + 4
    //         = 28 bytes.
    // SOME/IP length field counts bytes from Request ID onwards:
    //   8 (request_id + proto/iface/msgtype/retcode) + 28 (payload) = 36.
    constexpr std::uint32_t kEntriesLen = 16;
    constexpr std::uint32_t kOptionsLen = 0;
    constexpr std::uint32_t kLengthField = sdSomeIpLengthField(kEntriesLen, kOptionsLen);

    std::vector<std::uint8_t> b;
    b.reserve(44);

    appendSdHeader(b, p.session_id, kLengthField, p.sd_flags, kEntriesLen, p.sd_reserved);

    // FindService entry (16B) — no option referenced (option_run = 0).
    appendSdType1Entry(b, sd_entry_type::kFindService, /*index_first_run=*/0,
                       /*option_run=*/0, p.target.service_id, p.target.instance_id,
                       p.target.major_version, p.target.ttl, p.target.minor_version);

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
    constexpr std::uint32_t kEntriesLen   = 16;
    constexpr std::uint32_t kOptionsLen   = 0;
    constexpr std::uint32_t kLengthField  = sdSomeIpLengthField(kEntriesLen, kOptionsLen);

    std::vector<std::uint8_t> b;
    b.reserve(44);

    // Reboot|Unicast flags; OEM override sets the Reboot bit. Reserved canonically 0.
    appendSdHeader(b, t.session_id, kLengthField, t.sd_flags, kEntriesLen, t.sd_reserved);

    // OfferService entry (16B) — no option referenced; ttl == 0 -> StopOfferService.
    appendSdType1Entry(b, sd_entry_type::kOfferService, /*index_first_run=*/0,
                       /*option_run=*/0, t.service_id, t.instance_id, t.major_version,
                       t.ttl, t.minor_version);

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
    // 56 B Offer: the entry references (#Opt1=1) one Type-0x04 IPv4 Endpoint option at
    // options index 0 — the tester advertises its own L4 data endpoint. Any
    // `t.extra_options` are appended after it and also referenced (#Opt1 = 1 + N),
    // growing OptionsLen and the SOME/IP Length; empty (the default) keeps the 56-byte
    // single-option shape byte-identical.
    // Length = 8 + 4 (flags) + 4 (EntriesLen) + 16 (entry) + 4 (OptionsLen) + options.
    constexpr std::uint32_t kEntriesLen = 16;
    std::uint32_t extra_bytes = 0;
    for (const auto &eo : t.extra_options) {
        extra_bytes += static_cast<std::uint32_t>(4u + eo.body.size());  // Len2+Type1+Reserved1+body
    }
    const std::uint32_t options_len  = 12u + extra_bytes;   // endpoint(12) + extras
    const std::uint32_t length_field = sdSomeIpLengthField(kEntriesLen, options_len);
    // #Opt1 is a 4-bit nibble: the mandatory endpoint + extras must fit in 15 refs.
    assert(t.extra_options.size() <= 14u && "OfferService #Opt1 exceeds the 4-bit nibble");
    const std::uint8_t  num_opt1     = static_cast<std::uint8_t>(1u + t.extra_options.size());

    std::vector<std::uint8_t> b;
    b.reserve(44u + options_len);

    // Reboot|Unicast flags; OEM override sets the Reboot bit. Reserved canonically 0.
    appendSdHeader(b, t.service.session_id, length_field, t.service.sd_flags, kEntriesLen,
                   t.service.sd_reserved);
    appendSdType1Entry(b, sd_entry_type::kOfferService, /*index_first_run=*/0,
                       sdEntryOptionRun(num_opt1), t.service.service_id, t.service.instance_id,
                       t.service.major_version, t.service.ttl, t.service.minor_version);
    putBe32(b, options_len);
    appendIpv4EndpointOption(b, sd_option_type::kIpv4Endpoint, t.endpoint);   // options[0]
    for (const auto &eo : t.extra_options) {                                  // options[1..]
        appendSdExtraOption(b, eo);
    }
    return b;
}

std::vector<std::uint8_t>
buildOfferServiceWithEndpointAndSdEndpointOption(const OfferServiceWithEndpointTarget &data_ep,
                                                 const Ipv4Endpoint &sd_ep) {
    // 68 B Offer carrying TWO options: a Type-0x24 IPv4 SD Endpoint option at
    // options[0] (the redirect target `sd_ep`, read by a DUT client at message level)
    // and a Type-0x04 IPv4 Endpoint option at options[1] (the service data endpoint
    // `data_ep.endpoint`, which the ENTRY references at IndexFirstOptionRun = 1).
    // Unlike a FindService (a query, no endpoint), an OfferService without a data
    // endpoint is dropped as an unknown offer — so the redirect Offer carries both.
    // Length = 8 + 4 (flags) + 4 (EntriesLen) + 16 (entry) + 4 (OptionsLen) + 24 = 60.
    constexpr std::uint32_t kEntriesLen      = 16;
    constexpr std::uint32_t kOptionsLen      = 24;  // two 12-byte options
    constexpr std::uint32_t kLengthField     = sdSomeIpLengthField(kEntriesLen, kOptionsLen);
    constexpr std::uint8_t  kDataEndpointIdx = 1;   // entry references options[1]

    std::vector<std::uint8_t> b;
    b.reserve(68);

    // Reboot|Unicast flags; OEM override sets the Reboot bit. Reserved canonically 0.
    appendSdHeader(b, data_ep.service.session_id, kLengthField, data_ep.service.sd_flags,
                   kEntriesLen, data_ep.service.sd_reserved);
    // Entry references one option (the 0x04 data endpoint) starting at options[1]; the
    // 0x24 at options[0] is not entry-referenced (a DUT client reads it at message level).
    appendSdType1Entry(b, sd_entry_type::kOfferService, kDataEndpointIdx, kEntryOptionRun1,
                       data_ep.service.service_id, data_ep.service.instance_id,
                       data_ep.service.major_version, data_ep.service.ttl,
                       data_ep.service.minor_version);
    putBe32(b, kOptionsLen);
    appendIpv4EndpointOption(b, sd_option_type::kIpv4SdEndpoint, sd_ep);           // options[0]
    appendIpv4EndpointOption(b, sd_option_type::kIpv4Endpoint, data_ep.endpoint);  // options[1]
    return b;
}

std::vector<std::uint8_t>
buildOfferServiceWithEndpointAndConfigOption(const OfferServiceWithEndpointTarget &data_ep,
                                             const std::vector<std::pair<std::string, std::string>> &config_items) {
    // Options array: options[0] = Type-0x04 IPv4 Endpoint (the data endpoint, so the
    // Offer is accepted rather than dropped as an unknown offer), options[1] =
    // Type-0x01 Configuration option. The entry references BOTH (IndexFirstOptionRun=0,
    // #Opt1=2): a Configuration option is delivered only when the entry references it.
    // The options array is variable-length (the config string grows with the items),
    // so OptionsLen and the SOME/IP Length field are computed, not compile-time fixed.
    std::vector<std::uint8_t> opts;
    appendIpv4EndpointOption(opts, sd_option_type::kIpv4Endpoint, data_ep.endpoint);  // options[0]
    appendConfigurationOption(opts, config_items);                                    // options[1]

    constexpr std::uint32_t kEntriesLen = 16;
    const std::uint32_t options_len = static_cast<std::uint32_t>(opts.size());
    const std::uint32_t length_field = sdSomeIpLengthField(kEntriesLen, options_len);

    std::vector<std::uint8_t> b;
    b.reserve(44u + opts.size());
    // Reboot|Unicast flags; OEM override sets the Reboot bit. Reserved canonically 0.
    appendSdHeader(b, data_ep.service.session_id, length_field, data_ep.service.sd_flags,
                   kEntriesLen, data_ep.service.sd_reserved);
    appendSdType1Entry(b, sd_entry_type::kOfferService, /*index_first_run=*/0,
                       kEntryTwoOptionsRun1, data_ep.service.service_id,
                       data_ep.service.instance_id, data_ep.service.major_version,
                       data_ep.service.ttl, data_ep.service.minor_version);
    putBe32(b, options_len);
    b.insert(b.end(), opts.begin(), opts.end());
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

std::vector<std::uint8_t> buildMultiOfferService(const MultiOfferServiceParams &p) {
    // Same wire layout as buildMultiSubscribeEventgroup but with N Type-1 OfferService
    // entries: all share one referenced IPv4 Endpoint option (run 0 → option index 0,
    // #Opt1=1 per entry). EntriesLen = 16 * N; OptionsLen = 12 (the single endpoint).
    const std::uint32_t entries_len    = static_cast<std::uint32_t>(16 * p.entries.size());
    constexpr std::uint32_t kOptionsLen = 12;  // one shared IPv4 Endpoint option
    const std::uint32_t length_field   = sdSomeIpLengthField(entries_len, kOptionsLen);

    std::vector<std::uint8_t> b;
    b.reserve(16u + 8u + entries_len + 4u + kOptionsLen);
    appendSdHeader(b, p.session_id, length_field, p.sd_flags, entries_len, p.sd_reserved);
    for (const auto &e : p.entries) {
        appendSdType1Entry(b, sd_entry_type::kOfferService, /*index_first_run=*/0,
                           kEntryOptionRun1, e.service_id, e.instance_id, e.major_version,
                           e.ttl, e.minor_version);
    }
    putBe32(b, kOptionsLen);
    appendIpv4EndpointOption(b, sd_option_type::kIpv4Endpoint, p.endpoint);
    return b;
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
    // timing.total_emits, always < 0xFFFF in practice), so Reboot stays 1 on
    // every emit and the Unicast-only (sd_flags::kUnicast) value is unused here.
    constexpr std::uint8_t kSdFlagsBoot = ::tc8::sd_flags::kRebootUnicast;

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
    constexpr std::uint32_t kEntriesLenCanonical = 16;
    constexpr std::uint32_t kOptionsLenCanonical = 12;
    // Each extra option contributes (length 2B + type 1B + reserved 1B + body
    // bytes) to the Options Array. Sum once for downstream length math.
    std::uint32_t extra_options_total_bytes = 0;
    for (const auto& eo : p.extra_options) {
        extra_options_total_bytes += static_cast<std::uint32_t>(4 + eo.body.size());
    }
    // Optional second IPv4 Endpoint option is a fixed canonical 12 bytes.
    const std::uint32_t second_endpoint_bytes = p.second_endpoint.has_value() ? 12u : 0u;
    const std::uint32_t length_field = p.length_override.value_or(sdSomeIpLengthField(
        kEntriesLenCanonical, kOptionsLenCanonical + second_endpoint_bytes + extra_options_total_bytes));
    const std::uint32_t entries_len_field =
        p.entries_len_override == 0 ? kEntriesLenCanonical : p.entries_len_override;
    const std::uint32_t options_len_field = p.options_len_override.value_or(
        kOptionsLenCanonical + second_endpoint_bytes + extra_options_total_bytes);
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
    const std::uint8_t entry_byte3 = sdEntryOptionRun(num_options_first, num_options_second);
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
    b.reserve(56 + second_endpoint_bytes + p.extra_trailing_payload.size());

    // Header preamble via the SD SSOT. ETS_178 drives method_id_field;
    // ETS_123/_124/_125 inject a malformed entries_len_field; the Reserved
    // field is canonically 0 here (FindService owns the reserved override).
    appendSdHeader(b, p.session_id, length_with_trailing, p.sd_flags, entries_len_field,
                   /*reserved=*/0, method_id_field);

    // SubscribeEventgroup entry (16B, Type 2) via the entry SSOT. The option-run
    // bytes are override-driven (ETS_115/_117/_173); a case may set Reserved bits
    // (byte 12 + high nibble of 13) for an implementation-defined entry flag.
    SdType2EntryFields entry;
    entry.entry_type = sd_entry_type::kSubscribeEventgroup;
    entry.index_first_run = index_first;
    entry.index_second_run = index_second;
    entry.option_run = entry_byte3;
    entry.service_id = p.target.service_id;
    entry.instance_id = p.target.instance_id;
    entry.major_version = p.target.major_version;
    entry.ttl = p.target.ttl;
    entry.entry_reserved = p.target.entry_reserved.value_or(0);
    entry.counter = p.target.counter;
    entry.eventgroup_id = p.target.eventgroup_id;
    appendSdType2Entry(b, entry);

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

    // Optional second IPv4 Endpoint option (canonical 12B via the SSOT
    // encoder) — the dual-transport SubscribeEventgroup a mixed-reliability
    // (RT_BOTH) eventgroup requires. Emitted before any raw `extra_options` so
    // options [UDP, TCP] are contiguous from index 0 and the entry's first
    // option run (#Opt1=2) references both.
    if (p.second_endpoint.has_value()) {
        appendIpv4EndpointOption(b, sd_option_type::kIpv4Endpoint, *p.second_endpoint);
    }

    // §5.1.6 SOMEIP_ETS_175 extra options appended after the canonical IPv4
    // Endpoint option, via the shared appendSdExtraOption SSOT (spec-correct
    // Length = Reserved + body).
    for (const auto& eo : p.extra_options) {
        appendSdExtraOption(b, eo);
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

void setDualEndpointSubscribe(SubscribeEventgroupParams &p, const Ipv4Endpoint &tcp_endpoint) {
    Ipv4Endpoint tcp = tcp_endpoint;
    tcp.l4proto = 0x06;  // TCP — option 1 of the UDP+TCP dual-transport Subscribe.
    p.second_endpoint = tcp;
    // Entry's first option run references BOTH options (options[0]=UDP,
    // options[1]=TCP): vsomeip's mixed-eventgroup check requires both ports set
    // with distinct reliability.
    p.num_options_first_override = std::uint8_t{2};
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
    const std::uint32_t entries_len_actual =
        static_cast<std::uint32_t>(16 * p.entries.size());
    // §5.1.6 SOMEIP_ETS_114: caller-supplied entries_len_override (non-zero)
    // injects a value diverging from the actual entry-bytes count; default
    // (0) means "use the actual computed value".
    const std::uint32_t entries_len =
        p.entries_len_override == 0 ? entries_len_actual : p.entries_len_override;
    // A mixed-reliability bundle (e.g. one containing eg 0x0002) carries a second
    // (TCP) endpoint option, so the Options Array is 24 B. Each entry references
    // either just the UDP option (#Opt1=1, an unreliable eventgroup) or both
    // UDP + TCP (#Opt1=2, a mixed one) — per `per_entry_num_options_first`, or the
    // dual/single default when that is empty.
    const bool dual_option = p.second_endpoint.has_value();
    const std::uint32_t kOptionsLen = dual_option ? 24u : 12u;
    const std::uint8_t default_num_opt1 = dual_option ? std::uint8_t{2} : std::uint8_t{1};
    // SOME/IP Length field still counts the ACTUAL entries bytes (so the
    // wire layout is internally consistent: header reads X entries-bytes
    // even when EntriesLen field lies). The mismatch is the spec hook.
    const std::uint32_t length_field = sdSomeIpLengthField(entries_len_actual, kOptionsLen);

    std::vector<std::uint8_t> b;
    b.reserve(16 + 4 + 4 + entries_len + 4 + kOptionsLen);

    // EntriesLen may be a deliberately-malformed ETS_114 value; the Length field
    // above still counts the ACTUAL entry bytes (the internal-consistency hook).
    appendSdHeader(b, p.session_id, length_field, p.sd_flags, entries_len);

    for (std::size_t i = 0; i < p.entries.size(); ++i) {
        const auto &t = p.entries[i];
        // Each entry references its option run(s) from index 0: #Opt1 options in
        // run 1 (per-entry override or the dual/single default).
        const std::uint8_t num_opt1 =
            i < p.per_entry_num_options_first.size()
                ? static_cast<std::uint8_t>(p.per_entry_num_options_first[i] & 0x0F)
                : default_num_opt1;
        SdType2EntryFields entry;
        entry.entry_type = sd_entry_type::kSubscribeEventgroup;
        entry.index_first_run = 0;
        entry.index_second_run = 0;
        entry.option_run = sdEntryOptionRun(num_opt1);  // #Opt1 | #Opt2=0
        entry.service_id = t.service_id;
        entry.instance_id = t.instance_id;
        entry.major_version = t.major_version;
        entry.ttl = t.ttl;
        entry.entry_reserved = t.entry_reserved.value_or(0);
        entry.counter = t.counter;
        entry.eventgroup_id = t.eventgroup_id;
        appendSdType2Entry(b, entry);
    }

    putBe32(b, kOptionsLen);

    // IPv4 Endpoint option(s) via the shared endpoint-option encoder: option 0
    // is the UDP endpoint; a mixed-reliability bundle appends option 1 (TCP).
    appendIpv4EndpointOption(b, sd_option_type::kIpv4Endpoint, p.tester_endpoint);
    if (dual_option) {
        appendIpv4EndpointOption(b, sd_option_type::kIpv4Endpoint, *p.second_endpoint);
    }

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
    p.sd_flags = ::tc8::sd_flags::kRebootUnicast;
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
    constexpr std::uint8_t kSdFlagsBoot = ::tc8::sd_flags::kRebootUnicast;

    return runBootCadence(timing, [&](int i) {
        return subscribeOnce(target, kSdFlagsBoot,
                             static_cast<std::uint16_t>(0x0001 + i), iface, dest);
    });
}

int emitSubscribeEventgroupBootTcpOption(std::string_view iface, const SubscribeEventgroupTarget &target,
                                         const BootTiming &timing, const SubscribeDestination &dest) {
    constexpr std::uint8_t kSdFlagsBoot = ::tc8::sd_flags::kRebootUnicast;
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
    constexpr std::uint16_t kOptionBodyLen = 9;  // IPv4 Multicast option body size.

    const bool has_option = p.target.multicast_endpoint.has_value();
    const std::uint32_t options_len = has_option ? 12u : 0u;
    // Length counts from Request ID onward: 8 + SD flags(4) + EntriesLen(4)
    // + entry(16) + OptionsLen(4) + option bytes.
    const std::uint32_t length_field = sdSomeIpLengthField(kEntriesLen, options_len);

    std::vector<std::uint8_t> b;
    b.reserve(16 + 4 + 4 + 16 + 4 + options_len);

    appendSdHeader(b, p.session_id, length_field, p.sd_flags, kEntriesLen);

    // SubscribeEventgroupAck entry (16B, Type 0x07) via the entry SSOT. TTL == 0
    // makes it a Nack; one option referenced only when a multicast endpoint is set.
    SdType2EntryFields entry;
    entry.entry_type = sd_entry_type::kSubscribeEventgroupAck;
    entry.index_first_run = 0;
    entry.index_second_run = 0;
    entry.option_run = has_option ? kEntryOptionRun1 : static_cast<std::uint8_t>(0);
    entry.service_id = p.target.service_id;
    entry.instance_id = p.target.instance_id;
    entry.major_version = p.target.major_version;
    entry.ttl = p.target.ttl;
    entry.entry_reserved = p.target.entry_reserved.value_or(0);
    entry.counter = p.target.counter;
    entry.eventgroup_id = p.target.eventgroup_id;
    appendSdType2Entry(b, entry);

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
