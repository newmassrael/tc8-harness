#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "tc8/protocol_frames/someip_frame.h"

#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying fields parsed from an observed SOME/IP
// frame. Matching SCXML declaration:
//   <sce:context id="captured" cpp:type="tc8::SomeIpCaptured"
//                cpp:include="sce_integration/someip_captured.h"/>
//
// `TestCaseTraits<SM>::dispatch` copies the relevant fields out of the
// incoming `::tc8::SomeIpFrame` (carried inside the CapturedEvent variant)
// before raising the SCXML transition event. Cases that need fields from
// multiple protocols should define their own captured Context type rather
// than extending this one — this struct is the common-case shorthand for
// §5.1 SOMEIPSRV / SOMEIP_ETS cases.
//
// Expected values (configured SERVICE-ID-1 identity injected via `--expect`)
// live in a sibling `SomeIpExpected` context declared alongside this one —
// see `someip_expected.h`.
//
// SD payload fields (`sd_*`) hold values parsed from an SD payload
// (§7.3 wire format). They stay at 0 for non-SD frames or when the payload
// is shorter than the required boundary; guards that inspect them must
// confirm `service_id == 0xFFFF` and the relevant length invariant.

// Single SOME/IP-SD entry (16 bytes on the wire, §7.1). Layout of the
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

    // Type 2 interpretation of bytes 12..15.
    std::uint16_t reserved_counter = 0;  // bytes 12..13 (Reserved | Counter).
    std::uint16_t eventgroup_id = 0;     // bytes 14..15.
};

// Single SOME/IP-SD option (§7.3 Options Array). Wire layout for IPv4
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

// Type values defined by SOMEIPSD §4.2.2 / SWS_SD §7.3 Table 11.
// Declared before SomeIpCaptured so its inline helpers (e.g.
// sd_distinct_endpoint_ports_for_l4) can name the constants — inline
// member function bodies look up qualified names at class-completion
// scope, which excludes anything declared later in the same file.
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

struct SomeIpCaptured {
    std::uint16_t service_id = 0;
    std::uint16_t method_id = 0;
    std::uint32_t length = 0;
    std::uint16_t client_id = 0;
    std::uint16_t session_id = 0;
    std::uint8_t protocol_version = 0;
    std::uint8_t interface_version = 0;
    std::uint8_t message_type = 0;
    std::uint8_t return_code = 0;
    std::uint32_t payload_len = 0;

    // pcap arrival timestamp surfaced from `SomeIpFrame::observed_ts_us`
    // on every dispatch. `prev_observed_ts_us` snapshots `observed_ts_us`
    // ONLY when the SCXML transitions on a fired frame (managed in
    // `_someipsrv_traits_base.h::SomeIpAnyBase::dispatch`), so non-fired
    // frames between two state advances never pollute the gap. First
    // fired transition sees `prev=0` → `frame_delta_us()` returns
    // `observed_ts_us` itself, so guards on the very first transition
    // must depend only on structural conjuncts (service_id, entry type,
    // ...) — not on the delta. §5.1.5.4 SD_BEHAVIOR_01/_02 read the
    // delta from the second fired transition onward.
    std::int64_t observed_ts_us = 0;
    std::int64_t prev_observed_ts_us = 0;
    std::int64_t frame_delta_us() const { return observed_ts_us - prev_observed_ts_us; }

    // Snapshot of `session_id` from the previous fired SOME/IP-SD frame,
    // managed by the same dispatch hook that updates `prev_observed_ts_us`.
    // §5.1.6 SOMEIP_ETS_091 reads it to assert OfferService Session-IDs
    // strictly increment across consecutive observations
    // (PRS_SOMEIPSD_00154 / 00157 / 00355). First fired transition sees
    // `prev_sd_session_id == 0` (sentinel) so guards on the very first
    // transition must not depend on the delta — phase 1 snapshots the
    // initial value, phase 2 onward asserts strict increase.
    std::uint16_t prev_sd_session_id = 0;

    // Transport 4-tuple from the encapsulating UDP datagram or TCP
    // segment (NBO IPs, host-order ports). §5.1.5.6 ONWIRE_01 verifies
    // the DUT-controlled src half of the Response (src_ip == DUT iface
    // IP, src_port == SERVICE-ID-1 UDP port). The dst half is kernel-
    // routing responsibility (return path is determined by the
    // Request's source address) and is implicitly verified by the
    // Response arriving at all — surfacing it here keeps the option
    // open for future cases that want to assert it explicitly.
    std::uint32_t src_ip = 0;
    std::uint32_t dst_ip = 0;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;

    // First byte of the SOME/IP payload, or 0 when the frame carries no
    // payload. RPC §5.1.5.7 setter cases (RPC_11) need to verify the DUT
    // echoed back the value the tester wrote (UInt8 field → 1-byte
    // payload). A single-byte slot keeps the Captured surface flat
    // without committing to a variable-length copy.
    std::uint8_t payload_byte0 = 0;

    // First `kMaxPayloadBytes` bytes of the SOME/IP payload — wider
    // surface than `payload_byte0` for §5.1.6 SOMEIP_ETS Method
    // Response echo verification. ETS_005 (checkByteOrder UInt32 BE
    // sum, 4 bytes), ETS_008 (echoCommonDatatypes reversed-args, first
    // 8 bytes carry the echoed Double res1), and similar future cases
    // index distinct positions to pin DUT-side serialisation. Bytes
    // beyond `payload_len` stay 0; a 16-byte cap covers every echo
    // assertion the seed cluster needs without committing to a heap
    // copy of the full request/response payload (CommonAPI struct
    // echoes peak at ≤ 28 bytes, but assertions are always against a
    // discriminating prefix).
    static constexpr std::size_t kMaxPayloadBytes = 16;
    std::uint8_t payload_bytes[kMaxPayloadBytes]{};

    // Tester-side TCP socket state populated by §5.1.6 SOMEIP_ETS_037
    // stimulus before SCXML start(). Set from
    // `getsockopt(SOL_TCP, TCP_INFO).tcpi_state` after the post-reset
    // observation window — TCP_ESTABLISHED (=1) means the DUT did NOT
    // emit FIN per spec; TCP_CLOSE_WAIT (=8) means the DUT emitted FIN
    // (= test failure shape). Default 0 keeps the field a no-op for
    // every other case; `fillSomeIpCapturedFromFrame` never overwrites
    // it so subsequent SOME/IP frame dispatches preserve the verdict
    // signal across phase 2 → phase 3 transitions.
    std::uint8_t tcp_peer_state = 0;

    // §5.1.6 SOMEIP_ETS_097 verdict slot — set to 1 by the stimulus chain
    // when the tester-side TCP listener accepts an inbound SYN within the
    // accept timeout window. Stays 0 if the DUT never retried the connection
    // after the first refusal (= test failure shape). Like `tcp_peer_state`
    // it is preserved across SOME/IP frame dispatches.
    std::uint8_t tcp_handshake_completed = 0;

    // §5.1.6 SOMEIP_ETS_081 verdict slot — incremented by the stimulus
    // chain's detached accept thread on every successful inbound TCP
    // handshake, so server-reboot recovery cases can assert "DUT closed
    // the old connection and opened a new one" via `tcp_handshake_count
    // >= 2` rather than a binary completed/not-completed flag. Distinct
    // from `tcp_handshake_completed` so ETS_097's existing exact-match
    // verdict semantics stay untouched.
    std::uint8_t tcp_handshake_count = 0;

    std::uint8_t sd_flags = 0;      // Byte 0 of SD payload: Reboot|Unicast|Reserved bits.
    std::uint32_t sd_reserved = 0;  // Bytes 1..3 of SD payload (24 bits, right-aligned).

    // Length of the entries array in bytes. Per SD §7.3 each entry is 16
    // bytes, so valid values are multiples of 16. Stays 0 when the payload
    // is too short to reach the entries-length field.
    std::uint32_t sd_entries_len = 0;

    // Length of the options array in bytes. Per SD §7.3 the options-length
    // field follows the entries array. Stays 0 when the payload is too
    // short to reach it.
    std::uint32_t sd_options_len = 0;

    // Parsed entries array. Population is capped at `kMaxSdEntries`; real
    // §5.1 traffic rarely exceeds 2-3 entries per SD message. Entries
    // beyond index `sd_entry_count - 1` stay default-constructed.
    static constexpr std::size_t kMaxSdEntries = 8;
    std::uint8_t sd_entry_count = 0;
    SdEntry sd_entries[kMaxSdEntries]{};

    // Parsed options array. vsomeip OfferService for service 0xF4E7 emits
    // two options (UDP + TCP IPv4 Endpoint); SubscribeAck for a multicast
    // eventgroup adds a third (IPv4 Multicast). Cap matches kMaxSdEntries
    // for symmetry — real §5.1 traffic stays below 4 options per SD frame.
    static constexpr std::size_t kMaxSdOptions = 8;
    std::uint8_t sd_option_count = 0;
    SdOption sd_options[kMaxSdOptions]{};

    // §5.1.5.3.9 SOMEIPSRV_SD_MESSAGE_09 cross-phase cache — UDP port
    // pulled from the most recent OfferService's IPv4 Endpoint Option
    // (option type 0x04, l4_proto 0x11). Updated by
    // `fillSomeIpCapturedFromFrame` on every OfferService observation,
    // preserved across non-OfferService frames so the case's Phase 3
    // Notification guard can compare `captured.src_port ==
    // captured.cached_offer_endpoint_udp_port` without an SCXML
    // datamodel. Stays 0 until an OfferService is observed; matches
    // (or differs from) the wire-source for that single observation
    // window.
    std::uint16_t cached_offer_endpoint_udp_port = 0;

    // Per-type counts for the two endpoint-bearing option types. Computed
    // alongside sd_option_count so SCXML guards can assert presence
    // ("DUT emitted >= 1 IPv4 Endpoint Option") without re-walking the
    // array. Cases that need a specific endpoint protocol (UDP vs TCP)
    // index into `sd_options[]` and inspect `l4_proto`.
    std::uint8_t sd_ipv4_endpoint_count = 0;
    std::uint8_t sd_ipv4_multicast_count = 0;

    // Returns true when at least one parsed option matches `(type, l4)`.
    // Used by OPTIONS_06/13/15 guards that assert "an IPv4 Endpoint
    // Option with L4-Proto = X is present" without committing to a fixed
    // array index (vsomeip orders the UDP/TCP options unpredictably).
    bool sd_has_option_with_l4(std::uint8_t want_type, std::uint8_t want_l4) const {
        for (std::uint8_t i = 0; i < sd_option_count; ++i) {
            if (sd_options[i].type == want_type && sd_options[i].l4_proto == want_l4) {
                return true;
            }
        }
        return false;
    }

    // Returns the first option matching `(type, l4)` as a const reference,
    // or a static empty option when none is present. Lets SCXML guards
    // chain field lookups (port, ipv4) on a logically-named protocol axis.
    const SdOption &sd_first_option_with_l4(std::uint8_t want_type, std::uint8_t want_l4) const {
        static constexpr SdOption kEmpty{};
        for (std::uint8_t i = 0; i < sd_option_count; ++i) {
            if (sd_options[i].type == want_type && sd_options[i].l4_proto == want_l4) {
                return sd_options[i];
            }
        }
        return kEmpty;
    }

    // Counts distinct port values across IPv4 Endpoint Options whose L4
    // matches `want_l4`. §5.1.5.7 RPC_14/_17 use this to assert that
    // two service-instances of the same service expose different UDP
    // (RPC_14) or TCP (RPC_17) ports — a 2-instance OfferService should
    // produce two distinct ports per L4 axis. Walks at most kMaxSdOptions
    // ports; collisions on the small fixed buffer are impossible because
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

// ADL hook called by `TestRunner<SM>` at construction. No-op for captured
// because captured fields get populated from wire frames, not from CLI
// configuration; the overload exists so the uniform `applyTestConfig(c, cfg)`
// call in TestRunner compiles for every Named Context type. Adding a new
// Context type means adding a matching overload in its own header; missing
// overloads fail at compile time rather than silently skipping configuration.
inline void applyTestConfig(SomeIpCaptured & /*c*/, const TestConfig & /*cfg*/) {
    // captured-from-wire fields have no CLI-driven initial values.
}

// Forward declaration — `fillSomeIpCapturedFromFrame` calls
// `parseSdHeaderInto`, and the latter is defined below to keep the SD
// wire-format documentation grouped in one place.
inline void parseSdHeaderInto(SomeIpCaptured &c, const std::uint8_t *payload, std::size_t payload_len);

// Decode the Options Array (§7.3, after the Entries Array). Caller passes
// the full SD payload; this routine seeks to the options block using the
// already-populated `sd_entries_len` and `sd_options_len` fields. Walks
// each option's [Length(2B BE), Type(1B), per-type tail] tuple, populates
// `sd_options[]` up to `kMaxSdOptions`, and updates per-type counts.
inline void parseSdOptionsInto(SomeIpCaptured &c, const std::uint8_t *payload, std::size_t payload_len);

// Shared fill logic for §5.1 cases whose dispatch() copies a SOME/IP
// frame into the captured context. Every SOMEIPSRV case used to carry
// a ~15-line copy block plus a guarded parseSdHeaderInto; centralizing
// here collapses dispatch() bodies to ~5 lines and keeps SD payload
// parsing gated on `service_id == 0xFFFF` so non-SD frames never push
// misaligned bytes through parseSdHeaderInto.
inline void fillSomeIpCapturedFromFrame(SomeIpCaptured &c, const SomeIpFrame &f) {
    c.service_id = f.service_id;
    c.method_id = f.method_id;
    c.length = f.length;
    c.client_id = f.client_id;
    c.session_id = f.session_id;
    c.protocol_version = f.protocol_version;
    c.interface_version = f.interface_version;
    c.message_type = f.message_type;
    c.return_code = f.return_code;
    c.payload_len = f.payload_len;
    c.payload_byte0 = (f.payload_data != nullptr && f.payload_len > 0) ? f.payload_data[0] : 0;
    {
        const std::size_t to_copy =
            (f.payload_data != nullptr) ? std::min<std::size_t>(SomeIpCaptured::kMaxPayloadBytes, f.payload_len) : 0;
        for (std::size_t i = 0; i < SomeIpCaptured::kMaxPayloadBytes; ++i) {
            c.payload_bytes[i] = (i < to_copy) ? f.payload_data[i] : 0;
        }
    }
    c.src_ip = f.src_ip;
    c.dst_ip = f.dst_ip;
    c.src_port = f.src_port;
    c.dst_port = f.dst_port;
    c.observed_ts_us = f.observed_ts_us;
    if (f.service_id == 0xFFFF) {
        parseSdHeaderInto(c, f.payload_data, f.payload_len);
        parseSdOptionsInto(c, f.payload_data, f.payload_len);
        // §5.1.5.3.9 cross-phase cache: OfferService (entry type 0x01)
        // with a UDP IPv4 Endpoint Option (type 0x04, l4_proto 0x11)
        // populates `cached_offer_endpoint_udp_port`. Non-OfferService
        // frames leave the cache untouched, so SD_MESSAGE_09's Phase 3
        // Notification guard can compare against the value learned in
        // Phase 1 without an SCXML datamodel.
        if (c.sd_entry_count > 0 && c.sd_entries[0].type == 0x01) {
            const auto &udp_endpoint = c.sd_first_option_with_l4(0x04, 0x11);
            if (udp_endpoint.port != 0) {
                c.cached_offer_endpoint_udp_port = udp_endpoint.port;
            }
        }
    }
}

// Peeks the first SD entry's Type byte without mutating a context — used
// by dispatch() filters that want to reject e.g. FindService echoes
// (type 0x00) before committing the frame's fields to ctx. The Type
// byte lives at offset 8 of the SD payload (after the 4-byte flags/
// reserved header and 4-byte entries-array length). Returns a sentinel
// 0xFF when the payload is too short to cover byte 8.
inline std::uint8_t peekSdEntry0Type(const std::uint8_t *payload, std::size_t payload_len) {
    constexpr std::uint8_t kSentinel = 0xFF;
    if (payload == nullptr || payload_len < 9) {
        return kSentinel;
    }
    return payload[8];
}

// Decode one 16-byte SD entry at `src` into `dst`. Both Type 1 and Type 2
// tail interpretations are filled so guards can pick the matching view
// without re-decoding the raw bytes.
inline void decodeSdEntry(SdEntry &dst, const std::uint8_t *src) {
    dst.type = src[0];
    dst.index_first = src[1];
    dst.index_second = src[2];
    dst.num_opt1 = static_cast<std::uint8_t>((src[3] >> 4) & 0x0F);
    dst.num_opt2 = static_cast<std::uint8_t>(src[3] & 0x0F);
    dst.service_id = static_cast<std::uint16_t>((static_cast<std::uint16_t>(src[4]) << 8) | src[5]);
    dst.instance_id = static_cast<std::uint16_t>((static_cast<std::uint16_t>(src[6]) << 8) | src[7]);
    dst.major_version = src[8];
    dst.ttl = (static_cast<std::uint32_t>(src[9]) << 16) | (static_cast<std::uint32_t>(src[10]) << 8) |
              static_cast<std::uint32_t>(src[11]);
    dst.minor_version = (static_cast<std::uint32_t>(src[12]) << 24) | (static_cast<std::uint32_t>(src[13]) << 16) |
                        (static_cast<std::uint32_t>(src[14]) << 8) | static_cast<std::uint32_t>(src[15]);
    dst.reserved_counter = static_cast<std::uint16_t>((static_cast<std::uint16_t>(src[12]) << 8) | src[13]);
    dst.eventgroup_id = static_cast<std::uint16_t>((static_cast<std::uint16_t>(src[14]) << 8) | src[15]);
}

// Parse the SD payload layout (§7.3): 4-byte header (Flags + Reserved),
// 4-byte LengthOfEntriesArray, Entries array (N * 16 bytes), 4-byte
// LengthOfOptionsArray. Fills sd_flags/sd_reserved when >= 4 bytes are
// available, sd_entries_len when >= 8 bytes are available, entries up to
// `kMaxSdEntries` when the payload covers them, and sd_options_len when
// the entries array is fully present. Fields the parser can't reach keep
// their default 0 — callers that care must gate on `service_id ==
// 0xFFFF` and on the relevant length invariant.
inline void parseSdHeaderInto(SomeIpCaptured &c, const std::uint8_t *payload, std::size_t payload_len) {
    if (payload == nullptr || payload_len < 4) {
        return;
    }
    c.sd_flags = payload[0];
    c.sd_reserved = (static_cast<std::uint32_t>(payload[1]) << 16) | (static_cast<std::uint32_t>(payload[2]) << 8) |
                    static_cast<std::uint32_t>(payload[3]);

    if (payload_len < 8) {
        return;
    }
    c.sd_entries_len = (static_cast<std::uint32_t>(payload[4]) << 24) | (static_cast<std::uint32_t>(payload[5]) << 16) |
                       (static_cast<std::uint32_t>(payload[6]) << 8) | static_cast<std::uint32_t>(payload[7]);

    // Parse entries. Each entry is 16 bytes and lives at payload offset
    // 8 + i*16. Stop early if the payload is truncated mid-entry, the
    // declared entries length is inconsistent (not a multiple of 16), or
    // we reach `kMaxSdEntries`.
    const std::uint32_t declared_entries_bytes = c.sd_entries_len;
    const std::size_t kEntriesStart = 8;
    std::uint8_t parsed = 0;
    for (std::size_t i = 0; i < SomeIpCaptured::kMaxSdEntries; ++i) {
        const std::size_t offset = kEntriesStart + i * 16;
        if (offset + 16 > payload_len) {
            break;
        }
        if (declared_entries_bytes < (i + 1) * 16) {
            break;
        }
        decodeSdEntry(c.sd_entries[i], payload + offset);
        parsed = static_cast<std::uint8_t>(i + 1);
    }
    c.sd_entry_count = parsed;

    // OptionsLen follows the entries array on the wire — read it even if
    // we stopped short of `kMaxSdEntries` (the declared entries length
    // tells us the full entries-array footprint regardless of parse cap).
    const std::size_t options_len_offset = kEntriesStart + declared_entries_bytes;
    if (options_len_offset + 4 <= payload_len) {
        const std::uint8_t *o = payload + options_len_offset;
        c.sd_options_len = (static_cast<std::uint32_t>(o[0]) << 24) | (static_cast<std::uint32_t>(o[1]) << 16) |
                           (static_cast<std::uint32_t>(o[2]) << 8) | static_cast<std::uint32_t>(o[3]);
    }
}

// SOMEIPSRV multi-service axis identity (§5.1.5.7 RPC_01/_02/_13).
// SERVICE-ID-2's SomeIpServiceID is fixed at codegen time
// (dut/ets/ets2.fdepl); pinning the literal here keeps the SCXML
// conds + traits + smoke-test variant config aligned without a
// parallel `--expect` tier for what is a single configured value.
namespace someipsrv_si2 {
inline constexpr std::uint16_t kServiceId      = 0xF4E8;
inline constexpr std::uint16_t kEventGroupId   = 0x0003;
inline constexpr std::uint16_t kMethodIdEcho   = 0x0008;
}  // namespace someipsrv_si2

// Test sentinels for §5.1.5.3 SD_MESSAGE_14..19 negative-axis cases.
// These are "unknown" identity values the harness sends in a Subscribe
// to drive a SubscribeEventgroupNack and verify the echoed field. The
// sentinels are spec-implicit (the spec body says "<UNKNOWN-SERVICE-ID>"
// without fixing a value); we pick 0xFFFE — just below the 0xFFFF
// FindService Any-Instance reserved value, so it can never collide with
// a real service identifier. Both stimulus traits (Subscribe target)
// and SCXML cond expressions (echo assertion) reference the same
// constant so the two sides stay in sync if the chosen sentinel ever
// moves.
//
// Per-axis sentinels for _17 (Instance ID + 1) and _18 (Major Version
// + 1) intentionally don't live here — they're configuration-derived
// (cfg.someip.instance_id / major_version + 1) and computed inline so
// the assertion follows whatever SERVICE-ID-1 identity the operator
// passes via --expect.
namespace sd_test_unknown {
inline constexpr std::uint16_t kServiceId    = 0xFFFE;
inline constexpr std::uint16_t kEventGroupId = 0xFFFE;
// RPC §5.1.5.7 UNKNOWN-METHOD-ID sentinel — used by RPC_05/_06/_09/
// _18/_19/_20 to drive a SOMEIP_RET_CODE_E_UNKNOWN_METHOD Error from
// the DUT. Picked just below the 0xFFFF value used elsewhere as
// "wildcard"; does not collide with any tc8-dut method (0x01..0x41).
inline constexpr std::uint16_t kMethodId     = 0xFFFE;
}  // namespace sd_test_unknown

inline void parseSdOptionsInto(SomeIpCaptured &c, const std::uint8_t *payload, std::size_t payload_len) {
    if (payload == nullptr) {
        return;
    }
    // Options array starts immediately after the 4-byte options-length
    // field, which itself follows the entries array. parseSdHeaderInto
    // populates sd_entries_len and sd_options_len; this routine is a no-op
    // when those length invariants haven't been reached.
    const std::size_t kEntriesStart = 8;
    const std::size_t options_len_offset = kEntriesStart + c.sd_entries_len;
    const std::size_t options_start = options_len_offset + 4;
    if (options_start > payload_len) {
        return;
    }
    const std::uint32_t declared_options_bytes = c.sd_options_len;
    if (declared_options_bytes == 0) {
        return;
    }

    std::size_t cursor = 0;
    std::uint8_t parsed = 0;
    std::uint8_t endpoint_count = 0;
    std::uint8_t multicast_count = 0;
    while (parsed < SomeIpCaptured::kMaxSdOptions && cursor + 3 <= declared_options_bytes &&
           options_start + cursor + 3 <= payload_len) {
        const std::uint8_t *o = payload + options_start + cursor;
        const std::uint16_t opt_len =
            static_cast<std::uint16_t>((static_cast<std::uint16_t>(o[0]) << 8) | o[1]);
        const std::uint8_t opt_type = o[2];
        // Total bytes this option occupies on the wire = 2 (Length) +
        // 1 (Type) + opt_len. Stop early on a truncated tail or an
        // inconsistent declared options-array length.
        const std::size_t opt_total = static_cast<std::size_t>(3) + opt_len;
        if (cursor + opt_total > declared_options_bytes) {
            break;
        }
        if (options_start + cursor + opt_total > payload_len) {
            break;
        }

        SdOption &dst = c.sd_options[parsed];
        dst.length = opt_len;
        dst.type = opt_type;

        // IPv4 Endpoint and IPv4 Multicast share the same 12-byte layout
        // (Length=0x0009). Other types' tails stay at default 0 — guards
        // for those would inspect Length/Type only.
        const bool decode_endpoint = (opt_type == sd_option_type::kIpv4Endpoint ||
                                      opt_type == sd_option_type::kIpv4Multicast ||
                                      opt_type == sd_option_type::kIpv4SdEndpoint) &&
                                     opt_total >= 12;
        if (decode_endpoint) {
            dst.reserved1 = o[3];
            // memcpy of 4 wire bytes preserves network byte order — the
            // resulting `ipv4` uint32 compares equal to expected.* values
            // produced by inet_pton (which stores `addr.s_addr` in NBO).
            std::memcpy(&dst.ipv4, &o[4], 4);
            dst.reserved2 = o[8];
            dst.l4_proto = o[9];
            dst.port = static_cast<std::uint16_t>((static_cast<std::uint16_t>(o[10]) << 8) | o[11]);
        }

        if (opt_type == sd_option_type::kIpv4Endpoint) {
            ++endpoint_count;
        } else if (opt_type == sd_option_type::kIpv4Multicast) {
            ++multicast_count;
        }

        cursor += opt_total;
        ++parsed;
    }
    c.sd_option_count = parsed;
    c.sd_ipv4_endpoint_count = endpoint_count;
    c.sd_ipv4_multicast_count = multicast_count;
}

}  // namespace tc8
