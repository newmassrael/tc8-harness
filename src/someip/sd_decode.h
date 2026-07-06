#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "someip/sd_wire_constants.h"  // sd_option_type / sd_l4_proto / sd_entry_type (neutral wire values)
#include "wire/wire_read.h"

// Neutral SOME/IP-SD payload decoder (docs/tech-debt.md TD-06/TD-05 north star:
// one authoritative decoder, pure presentation on top). This leaf owns the SD
// wire structs, the value namespaces, and the parse — expanding the
// someip_sd_wire.def SSOT once. BOTH the verdict layer (sce_integration/
// someip_captured.h, whose SomeIpCaptured mixes SdDecoded in as its "SD aspect")
// and the documentation-site presentation (cli/packet_summary.cpp) depend DOWN
// on this leaf, so neither re-decodes the wire and presentation no longer reaches
// up into the verdict layer for SD.

namespace tc8 {

// Single SOME/IP-SD entry (16 bytes on the wire, TR_SOMEIP §7.1). Layout of the
// trailing 4 bytes depends on entry type family:
//   Type 1 (FindService 0x00, OfferService / StopOffer 0x01):
//     bytes 12..15 = Minor Version (32-bit BE).
//   Type 2 (SubscribeEventgroup / StopSubscribe 0x06,
//           SubscribeEventgroupAck / Nack 0x07):
//     bytes 12..13 = Reserved(12b) | Counter(4b),
//     bytes 14..15 = Eventgroup ID.
// Both interpretations are populated on every entry so guards pick the
// one matching the entry's type without re-decoding raw bytes. Unused
// fields stay at 0 for the non-matching family.
struct SdEntry {
    std::uint8_t type = 0;
    std::uint8_t index_first = 0;
    std::uint8_t index_second = 0;
    std::uint8_t num_opt1 = 0;  // High nibble of byte 3.
    std::uint8_t num_opt2 = 0;  // Low nibble of byte 3.
    std::uint16_t service_id = 0;
    std::uint16_t instance_id = 0;
    std::uint8_t major_version = 0;
    std::uint32_t ttl = 0;  // 24-bit big-endian, right-aligned.

    // Type 1 interpretation of bytes 12..15.
    std::uint32_t minor_version = 0;

    // Type 2 interpretation of bytes 12..13 (Reserved:12 | Counter:4), decoded
    // into the SAME named fields the stimulus side sets on
    // SubscribeEventgroupTarget, so a verdict reads back exactly what a case
    // wrote (one data model on both sides). Both are public SOME/IP-SD fields.
    // `counter` (4-bit, TR_SOMEIP §7.1.3) distinguishes parallel subscriptions
    // of the same eventgroup.
    // `entry_reserved` (12-bit) is decoded RAW on purpose: any entry flag a
    // vendor encodes there — e.g. an Initial-Data-Requested bit — is
    // implementation-defined, so the OEM masks `entry_reserved` itself rather
    // than the public core naming a specific bit (symmetric with
    // someip_sd_builder.h SubscribeEventgroupTarget::entry_reserved).
    std::uint16_t entry_reserved = 0;  // bytes 12..13, high 12 bits.
    std::uint8_t counter = 0;          // bytes 12..13, low 4 bits.
    std::uint16_t eventgroup_id = 0;   // bytes 14..15.
};

// Single SOME/IP-SD option (TR_SOMEIP §7.3 Options Array). Wire layout for IPv4
// Endpoint (Type=0x04) and IPv4 Multicast (Type=0x14) options
// (PRS_SOMEIPSD §4.2.2 / SWS_SD_00209..00215, 00390..00396):
//
//   bytes  0..1  Length (16 bit, BE) — number of bytes after Type
//   byte   2     Type
//   byte   3     Reserved (first reserved field)
//   bytes  4..7  IPv4-Address (32 bit, BE on the wire; stored here in
//                network byte order to align with `parseIpv4Dotted`-
//                produced expected.* fields which use `addr.s_addr` from
//                inet_pton — every other Captured surface in this
//                codebase follows the same NBO convention)
//   byte   8     Reserved (second reserved field, after address)
//   byte   9     Layer-4 Protocol (0x06 TCP / 0x11 UDP)
//   bytes 10..11 Port Number (16 bit, BE; stored here host-order so SCXML
//                cond expressions can compare against decimal literals)
//
// Length is 0x0009 for both endpoint shapes (covers Reserved + Address +
// Reserved + L4-Proto + Port = 9 bytes). Configuration / Load Balancing
// options also live in the array; their type-specific tail is left at
// default 0 — guards that care about those types must check `type` first.
struct SdOption {
    std::uint16_t length = 0;
    std::uint8_t type = 0;
    std::uint8_t reserved1 = 0;
    std::uint32_t ipv4 = 0;
    std::uint8_t reserved2 = 0;
    std::uint8_t l4_proto = 0;
    std::uint16_t port = 0;
};

// Cap on a captured Configuration Option item's content bytes — config strings
// ("key=value") are short, so a longer item is truncated to this for assertion.
inline constexpr std::size_t kMaxSdConfigItemLen = 64;

// One length-prefixed item of a Configuration Option (type 0x01) body — the DNS
// TXT-like "key[=value]" encoding (PRS_SOMEIPSD / SWS_SD §7.3). `len` is the on-wire
// length byte; `bytes`/`captured` hold the item's content (truncated to the cap).
struct SdConfigItem {
    std::uint8_t len = 0;                          // on-wire length byte
    std::uint8_t captured = 0;                     // bytes stored (min(len, cap))
    std::uint8_t bytes[kMaxSdConfigItemLen] = {};  // item content (key / key=value)
};

// sd_option_type / sd_l4_proto / sd_entry_type wire values now live in the
// neutral leaf someip/sd_wire_constants.h (included above), so the wire builder
// shares the exact same constants without pulling in this decode logic.

// Decode one 16-byte SD entry at `src` into `dst`. Both Type 1 and Type 2 tail
// interpretations are filled so guards can pick the matching view without
// re-decoding the raw bytes; the entry field layout (offsets, widths, and the
// bit slices) is owned by someip_sd_wire.def and expanded here, so the decoder
// is a direct consumer of the SSOT, not a hand-mirror of it (docs/tech-debt.md TD-01).
inline void decodeSdEntry(SdEntry &dst, const std::uint8_t *src) {
#define TC8_SD_ENTRY_FIELD(group, member, off, size, shift, mask) \
    dst.member = static_cast<decltype(dst.member)>(              \
        (::tc8::wire::readBe(src + (off), (size)) >> (shift)) & (mask));
#include "someip/someip_sd_wire.def"
#undef TC8_SD_ENTRY_FIELD
}

// Decoded SOME/IP-SD payload — the "SD aspect" of a captured SOME/IP frame.
// SomeIpCaptured (the verdict DTO) mixes this in as a base, alongside its other
// captured-aspect mixins, so cond/case/recognizer code reads `captured.sd_*`
// unchanged; the documentation-site exporter decodes a standalone SdDecoded.
// Parse population is capped at kMaxSdEntries / kMaxSdOptions (real SD
// traffic stays well below); entries/options beyond the cap stay
// default-constructed.
struct SdDecoded {
    static constexpr std::size_t kMaxSdEntries = 8;
    // Fixed on-wire size of one SD entry (TR_SOMEIP §7.1). Single source for the
    // entries-array stride used by the parse loop and the wire-total count.
    static constexpr std::size_t kSdEntrySizeBytes = 16;
    static constexpr std::size_t kMaxSdOptions = 8;
    static constexpr std::size_t kMaxSdConfigItems = 8;

    std::uint8_t sd_flags = 0;      // Byte 0 of SD payload: Reboot|Unicast|Reserved bits.
    std::uint32_t sd_reserved = 0;  // Bytes 1..3 of SD payload (24 bits, right-aligned).

    // Length of the entries array in bytes (multiples of kSdEntrySizeBytes) and
    // of the options array. Stay 0 when the payload is too short to reach them.
    std::uint32_t sd_entries_len = 0;
    std::uint32_t sd_options_len = 0;

    std::uint8_t sd_entry_count = 0;
    SdEntry sd_entries[kMaxSdEntries]{};

    std::uint8_t sd_option_count = 0;
    SdOption sd_options[kMaxSdOptions]{};

    std::uint8_t sd_config_item_count = 0;
    SdConfigItem sd_config_items[kMaxSdConfigItems]{};

    // SD_MESSAGE_09 cross-phase cache — UDP port from the most recent
    // OfferService's IPv4 Endpoint Option (type 0x04, l4 UDP), so a Phase-3
    // Notification guard can compare against the Phase-1 value without a datamodel.
    std::uint16_t cached_offer_endpoint_udp_port = 0;

    // Per-type counts for the two endpoint-bearing option types (capped alongside
    // sd_option_count), so guards assert presence without re-walking the array.
    std::uint8_t sd_ipv4_endpoint_count = 0;
    std::uint8_t sd_ipv4_multicast_count = 0;

    // Uncapped on-wire totals for DISPLAY/diagnostics only (the documentation-site
    // exporter's SD summary, docs/tech-debt.md TD-09). Every verdict-facing count
    // above caps at kMaxSdEntries / kMaxSdOptions; these carry the true wire totals
    // so the site renders an accurate "+N more" / endpoint count for a frame that
    // exceeds the parse cap. Verdict guards MUST use the capped counts, never these.
    std::uint16_t sd_entry_count_wire = 0;
    std::uint16_t sd_ipv4_endpoint_count_wire = 0;

    // SSOT for the config-item key match: `item` is exactly `key` (the key with no
    // value) or `key=...`. The single rule shared by the first-match lookup and the
    // per-key count below, so the two can never drift.
    static bool sd_config_item_matches(std::string_view item, std::string_view key) {
        return item == key || (item.size() > key.size() && item.compare(0, key.size(), key) == 0 &&
                               item[key.size()] == '=');
    }

    // The first parsed config item matching `key` ("key" exactly, or "key=..."), or
    // nullptr if absent. The single match site the has-key / value-of helpers share.
    const SdConfigItem *sd_config_item_for(std::string_view key) const {
        for (std::uint8_t i = 0; i < sd_config_item_count; ++i) {
            const std::string_view item(reinterpret_cast<const char *>(sd_config_items[i].bytes),
                                        sd_config_items[i].captured);
            if (sd_config_item_matches(item, key)) {
                return &sd_config_items[i];
            }
        }
        return nullptr;
    }

    // True if any parsed config item is `key` (no value) or `key=...`.
    bool sd_config_has_key(std::string_view key) const { return sd_config_item_for(key) != nullptr; }

    // The value after `key=` for the first matching item; empty if the key is absent or
    // present without a value (`key` or `key=`). Reliable only when the matched item was
    // not truncated (its `captured == len`); a value longer than the capture cap is
    // silently clipped, which a caller needing exactness detects via that field pair.
    std::string sd_config_value_of(std::string_view key) const {
        const SdConfigItem *it = sd_config_item_for(key);
        if (it == nullptr) {
            return std::string();
        }
        const std::string_view item(reinterpret_cast<const char *>(it->bytes), it->captured);
        if (item.size() <= key.size()) {
            return std::string();  // "key" with no value
        }
        return std::string(item.substr(key.size() + 1));  // after "key="
    }

    // How many parsed config items carry `key` (either `key` with no value or `key=...`).
    // A Configuration Option MAY repeat the same key across items; the first-match lookup
    // above cannot express that, so a "same key appears N times" guard counts with this.
    std::uint8_t sd_config_count_key(std::string_view key) const {
        std::uint8_t n = 0;
        for (std::uint8_t i = 0; i < sd_config_item_count; ++i) {
            const std::string_view item(reinterpret_cast<const char *>(sd_config_items[i].bytes),
                                        sd_config_items[i].captured);
            if (sd_config_item_matches(item, key)) {
                ++n;
            }
        }
        return n;
    }

    // Returns true when at least one parsed option matches `(type, l4)`.
    // Used by OPTIONS_06/13/15 guards that assert "an IPv4 Endpoint Option with
    // L4-Proto = X is present" without committing to a fixed array index (vsomeip
    // orders the UDP/TCP options unpredictably).
    bool sd_has_option_with_l4(std::uint8_t want_type, std::uint8_t want_l4) const {
        for (std::uint8_t i = 0; i < sd_option_count; ++i) {
            if (sd_options[i].type == want_type && sd_options[i].l4_proto == want_l4) {
                return true;
            }
        }
        return false;
    }

    // Returns the first option matching `(type, l4)` as a const reference, or a
    // static empty option when none is present. Lets SCXML guards chain field
    // lookups (port, ipv4) on a logically-named protocol axis.
    const SdOption &sd_first_option_with_l4(std::uint8_t want_type, std::uint8_t want_l4) const {
        static constexpr SdOption kEmpty{};
        for (std::uint8_t i = 0; i < sd_option_count; ++i) {
            if (sd_options[i].type == want_type && sd_options[i].l4_proto == want_l4) {
                return sd_options[i];
            }
        }
        return kEmpty;
    }

    // Counts distinct port values across IPv4 Endpoint Options whose L4 matches
    // `want_l4`. RPC_14/_17 assert two service-instances of the same
    // service expose different UDP (RPC_14) or TCP (RPC_17) ports. Walks at most
    // kMaxSdOptions ports; collisions on the fixed buffer are impossible because
    // the cap is the array size.
    std::uint8_t sd_distinct_endpoint_ports_for_l4(std::uint8_t want_l4) const {
        std::uint16_t seen[kMaxSdOptions]{};
        std::uint8_t seen_count = 0;
        for (std::uint8_t i = 0; i < sd_option_count; ++i) {
            const SdOption &o = sd_options[i];
            if (o.type != sd_option_type::kIpv4Endpoint || o.l4_proto != want_l4) {
                continue;
            }
            bool already = false;
            for (std::uint8_t j = 0; j < seen_count; ++j) {
                if (seen[j] == o.port) {
                    already = true;
                    break;
                }
            }
            if (!already) {
                seen[seen_count++] = o.port;
            }
        }
        return seen_count;
    }
};

// Peeks the first SD entry's Type byte without a full parse — used by dispatch()
// filters that reject e.g. FindService echoes (type 0x00) before committing a
// frame's fields. The Type byte lives at offset 8 (after the 4-byte flags/
// reserved header and 4-byte entries-array length). Returns 0xFF when the
// payload is too short to cover byte 8.
inline std::uint8_t peekSdEntry0Type(const std::uint8_t *payload, std::size_t payload_len) {
    constexpr std::uint8_t kSentinel = 0xFF;
    if (payload == nullptr || payload_len < 9) {
        return kSentinel;
    }
    return payload[8];
}

// Parse an SD payload (TR_SOMEIP §7.3) fully into `d`: 4-byte header (Flags +
// Reserved), 4-byte LengthOfEntriesArray, Entries array (N * kSdEntrySizeBytes),
// 4-byte LengthOfOptionsArray, Options array. Fills what the payload covers;
// fields the parser can't reach keep their default 0. The caller gates on the
// frame being SD (header Service ID) before calling.
inline void parseSdInto(SdDecoded &d, const std::uint8_t *payload, std::size_t payload_len) {
    if (payload == nullptr || payload_len < 4) {
        return;
    }
#define TC8_SD_HEADER_FIELD(member, off, size, shift, mask) \
    d.member = static_cast<decltype(d.member)>(            \
        (::tc8::wire::readBe(payload + (off), (size)) >> (shift)) & (mask));
#include "someip/someip_sd_wire.def"
#undef TC8_SD_HEADER_FIELD

    if (payload_len < 8) {
        return;
    }
#define TC8_SD_ENTRIESLEN_FIELD(member, off, size, shift, mask) \
    d.member = static_cast<decltype(d.member)>(                \
        (::tc8::wire::readBe(payload + (off), (size)) >> (shift)) & (mask));
#include "someip/someip_sd_wire.def"
#undef TC8_SD_ENTRIESLEN_FIELD

    // Parse entries. Each entry is kSdEntrySizeBytes at offset 8 + i*size. Stop
    // early on a truncated payload, an inconsistent declared length, or the cap.
    const std::uint32_t declared_entries_bytes = d.sd_entries_len;
    const std::size_t kEntriesStart = 8;
    constexpr std::size_t kEntrySize = SdDecoded::kSdEntrySizeBytes;
    std::uint8_t parsed = 0;
    for (std::size_t i = 0; i < SdDecoded::kMaxSdEntries; ++i) {
        const std::size_t offset = kEntriesStart + i * kEntrySize;
        if (offset + kEntrySize > payload_len) {
            break;
        }
        if (declared_entries_bytes < (i + 1) * kEntrySize) {
            break;
        }
        decodeSdEntry(d.sd_entries[i], payload + offset);
        parsed = static_cast<std::uint8_t>(i + 1);
    }
    d.sd_entry_count = parsed;
    // Uncapped on-wire entry total for display (TD-09), counted like the options
    // walk: complete entries actually PRESENT in the payload — bounded by BOTH
    // the declared entries-array length and the captured bytes. A blind
    // declared/kEntrySize would over-report a truncated frame (fabricating
    // "+N more" for entries not on the wire) and could overflow the u16.
    const std::size_t entries_avail =
        payload_len > kEntriesStart ? payload_len - kEntriesStart : 0;
    const std::size_t present_entries_bytes =
        std::min<std::size_t>(declared_entries_bytes, entries_avail);
    d.sd_entry_count_wire = static_cast<std::uint16_t>(present_entries_bytes / kEntrySize);

    // OptionsLen follows the entries array on the wire — read it via the declared
    // entries length regardless of the parse cap.
    const std::size_t options_len_offset = kEntriesStart + declared_entries_bytes;
    if (options_len_offset + 4 <= payload_len) {
        const std::uint8_t *o = payload + options_len_offset;
        d.sd_options_len = (static_cast<std::uint32_t>(o[0]) << 24) |
                           (static_cast<std::uint32_t>(o[1]) << 16) |
                           (static_cast<std::uint32_t>(o[2]) << 8) | static_cast<std::uint32_t>(o[3]);
    }

    // Options array starts immediately after the 4-byte options-length field.
    const std::size_t options_start = options_len_offset + 4;
    if (options_start > payload_len) {
        return;
    }
    const std::uint32_t declared_options_bytes = d.sd_options_len;
    if (declared_options_bytes == 0) {
        return;
    }

    std::size_t cursor = 0;
    std::uint8_t opt_parsed = 0;
    std::uint8_t endpoint_count = 0;
    std::uint8_t multicast_count = 0;
    std::uint16_t wire_endpoints = 0;  // uncapped on-wire endpoint total (TD-09 display)
    bool config_seen = false;
    while (cursor + 3 <= declared_options_bytes &&
           options_start + cursor + 3 <= payload_len) {
        const std::uint8_t *o = payload + options_start + cursor;
        const std::uint16_t opt_len =
            static_cast<std::uint16_t>((static_cast<std::uint16_t>(o[0]) << 8) | o[1]);
        const std::uint8_t opt_type = o[2];
        // Total bytes this option occupies = 2 (Length) + 1 (Type) + opt_len.
        // Stop on a truncated tail or an inconsistent declared options length.
        const std::size_t opt_total = static_cast<std::size_t>(3) + opt_len;
        if (cursor + opt_total > declared_options_bytes) {
            break;
        }
        if (options_start + cursor + opt_total > payload_len) {
            break;
        }

        // Uncapped on-wire endpoint tally (TD-09 display); the walk continues
        // past the parse cap purely to finish this count.
        if (opt_type == sd_option_type::kIpv4Endpoint) ++wire_endpoints;

        // Store into the parsed arrays / verdict counts only up to the cap.
        if (opt_parsed >= SdDecoded::kMaxSdOptions) {
            cursor += opt_total;
            continue;
        }

        SdOption &dst = d.sd_options[opt_parsed];
        dst.length = opt_len;
        dst.type = opt_type;

        // IPv4 Endpoint and IPv4 Multicast share the same 12-byte layout
        // (Length=0x0009). Other types' tails stay at default 0.
        const bool decode_endpoint = (opt_type == sd_option_type::kIpv4Endpoint ||
                                      opt_type == sd_option_type::kIpv4Multicast ||
                                      opt_type == sd_option_type::kIpv4SdEndpoint) &&
                                     opt_total >= 12;
        if (decode_endpoint) {
            // Field layout owned by someip_sd_wire.def (TD-01 SSOT). TC8_SD_OPTION_ADDR
            // memcpy's the 4 wire bytes, preserving network byte order.
#define TC8_SD_OPTION_FIELD(member, off, size, shift, mask) \
            dst.member = static_cast<decltype(dst.member)>( \
                (::tc8::wire::readBe(o + (off), (size)) >> (shift)) & (mask));
#define TC8_SD_OPTION_ADDR(member, off) std::memcpy(&dst.member, o + (off), 4);
#include "someip/someip_sd_wire.def"
#undef TC8_SD_OPTION_FIELD
#undef TC8_SD_OPTION_ADDR
        }

        // Configuration Option (type 0x01): a Reserved byte then the DNS TXT-like
        // config string — length-prefixed "key[=value]" items, zero-length-terminated.
        if (opt_type == sd_option_type::kConfiguration && !config_seen && opt_len >= 1) {
            config_seen = true;
            dst.reserved1 = o[3];
            const std::uint8_t *cs = o + 4;           // after Length(2) + Type(1) + Reserved(1)
            const std::size_t cs_len = opt_len - 1u;  // option body minus the Reserved byte
            std::size_t p = 0;
            std::uint8_t items = 0;
            while (p < cs_len && items < SdDecoded::kMaxSdConfigItems) {
                const std::uint8_t item_len = cs[p];
                if (item_len == 0) {
                    break;  // zero-length byte terminates the sequence
                }
                ++p;
                if (p + item_len > cs_len) {
                    break;  // item runs past the option body — truncated
                }
                SdConfigItem &item = d.sd_config_items[items];
                item.len = item_len;
                item.captured = static_cast<std::uint8_t>(
                    item_len < kMaxSdConfigItemLen ? item_len : kMaxSdConfigItemLen);
                std::memcpy(item.bytes, cs + p, item.captured);
                p += item_len;
                ++items;
            }
            d.sd_config_item_count = items;
        }

        if (opt_type == sd_option_type::kIpv4Endpoint) {
            ++endpoint_count;
        } else if (opt_type == sd_option_type::kIpv4Multicast) {
            ++multicast_count;
        }

        cursor += opt_total;
        ++opt_parsed;
    }
    d.sd_option_count = opt_parsed;
    d.sd_ipv4_endpoint_count = endpoint_count;
    d.sd_ipv4_multicast_count = multicast_count;
    d.sd_ipv4_endpoint_count_wire = wire_endpoints;

    // SD_MESSAGE_09 cross-phase cache: an OfferService (entry type 0x01) carrying a
    // UDP IPv4 Endpoint Option populates cached_offer_endpoint_udp_port; other
    // frames leave it 0.
    if (d.sd_entry_count > 0 && d.sd_entries[0].type == sd_entry_type::kOfferService) {
        const SdOption &udp_endpoint =
            d.sd_first_option_with_l4(sd_option_type::kIpv4Endpoint, sd_l4_proto::kUdp);
        if (udp_endpoint.port != 0) {
            d.cached_offer_endpoint_udp_port = udp_endpoint.port;
        }
    }
}

}  // namespace tc8
