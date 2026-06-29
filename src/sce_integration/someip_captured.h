#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

#include "tc8/protocol_frames/someip_frame.h"

#include "autosar/someiptp.h"
#include "someip/protocol.h"
#include "sce_integration/captured_frame_timing.h"
#include "sce_integration/captured_l3_endpoints.h"
#include "sce_integration/captured_l4_ports.h"
#include "sce_integration/captured_payload_snapshot.h"
#include "sce_integration/captured_trace.h"
#include "sce_integration/someip_sd_wire.h"
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
// (TR_SOMEIP §7.3 wire format). They stay at 0 for non-SD frames or when the payload
// is shorter than the required boundary; guards that inspect them must
// confirm `service_id == 0xFFFF` and the relevant length invariant.

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

struct SomeIpCaptured : CapturedPayloadSnapshot, CapturedFrameTiming,
                        CapturedL3Endpoints, CapturedL4Ports {
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

    // Datagram grouping (UDP only), surfaced from `SomeIpFrame`. For a
    // message parsed out of a UDP datagram, `datagram_msg_index` is its
    // 0-based position within that datagram and `datagram_msg_count` the
    // total number of SOME/IP messages the datagram carried (1 = sole
    // message). Lets a case assert the DUT concatenated N messages into one
    // UDP payload (PRS_SOMEIP permits it; e.g. CAN-encapsulated SOME/IP
    // batching, DS_CN_0011). `datagram_msg_count` stays 0 for SOME/IP-over-
    // TCP (a reassembled byte stream has no datagram boundary), so gate any
    // datagram-packing assertion on a UDP case — on TCP it reads 0, never a
    // spurious 1. Because the dispatcher delivers a datagram's messages in
    // wire order, an SCXML can reconstruct datagram boundaries from the
    // index sequence (index resetting to 0 marks the next datagram) to bind
    // a specific group of messages together rather than trusting one event's
    // count in isolation.
    std::uint16_t datagram_msg_index = 0;
    std::uint16_t datagram_msg_count = 0;

    // Inter-frame timing surface (`observed_ts_us` / `prev_observed_ts_us`
    // / `frame_delta_us()`) is inherited from `CapturedFrameTiming`.
    // `observed_ts_us` is surfaced from `SomeIpFrame::observed_ts_us` on
    // every dispatch; `prev_observed_ts_us` snapshots it ONLY when the
    // SCXML transitions on a fired frame (managed in
    // `_someipsrv_traits_base.h::SomeIpAnyBase::dispatch`), so non-fired
    // frames between two state advances never pollute the gap. §5.1.5.4
    // SD_BEHAVIOR_01/_02 read the delta from the second fired transition
    // onward; both guard the delta with a two-sided bound, so the very
    // first transition (where the base returns 0) is rejected by the
    // lower bound and the structural conjuncts (service_id, entry type,
    // ...) carry it — unchanged from the prior local definition, which
    // returned `observed_ts_us` itself on the first frame and was
    // rejected by the same conds' upper bound instead.

    // Snapshot of `session_id` from the previous fired SOME/IP-SD frame,
    // managed by the same dispatch hook that updates `prev_observed_ts_us`.
    // §5.1.6 SOMEIP_ETS_091 reads it to assert OfferService Session-IDs
    // strictly increment across consecutive observations
    // (PRS_SOMEIPSD_00154 / 00157 / 00355). First fired transition sees
    // `prev_sd_session_id == 0` (sentinel) so guards on the very first
    // transition must not depend on the delta — phase 1 snapshots the
    // initial value, phase 2 onward asserts strict increase.
    std::uint16_t prev_sd_session_id = 0;

    // SOME/IP-TP segment header (PRS_SOMEIP §4.2.1.4), parsed when the message_type
    // carries the TP-Flag (someiptp::kMessageTypeTpFlag = 0x20). `is_tp` is false for a
    // non-segmented message and the rest stay default. The header bit layout is decoded
    // by someiptp::parseTpHeader — the single source of that wire format, shared with
    // the Reassembler.
    bool          is_tp = false;
    std::uint32_t tp_offset = 0;        // byte offset of this segment's payload (16-aligned)
    bool          tp_more_segments = false;
    std::uint32_t tp_segment_len = 0;   // segment payload bytes (frame payload minus the 4-byte TP header)

    // Snapshot of `tp_more_segments` from the previous fired TP-segment frame,
    // managed by the same dispatch hook that updates `prev_sd_session_id`, so a
    // SOMEIPGEN_TP case can compare consecutive segments. TP_07 (More-Segments
    // flag sequence — the final segment clears the flag a predecessor set) reads
    // `prev_tp_more_segments` (sentinel false on the first fired transition).
    // TP_05 (all segments share one Session ID) needs NO TP-specific field: the
    // unconditional `prev_sd_session_id` snapshot already holds the previous
    // fired frame's session_id, so the case asserts `session_id ==
    // prev_sd_session_id`. A dedicated prev_tp_session_id would be a
    // byte-identical duplicate of it (same value, same snapshot point).
    bool          prev_tp_more_segments = false;

    // Transport 4-tuple (`src_ip` / `dst_ip` / `src_port` / `dst_port`)
    // from the encapsulating UDP datagram or TCP segment is inherited
    // from `CapturedL3Endpoints` + `CapturedL4Ports`. §5.1.5.6 ONWIRE_01
    // verifies the DUT-controlled src half of the Response (src_ip == DUT
    // iface IP, src_port == SERVICE-ID-1 UDP port). The dst half is
    // kernel-routing responsibility (return path is determined by the
    // Request's source address) and is implicitly verified by the
    // Response arriving at all — surfacing it keeps the option open for
    // future cases that want to assert it explicitly.

    // The SOME/IP payload snapshot (`payload_snapshot` /
    // `payload_snapshot_len`, capacity `kMaxPayloadSnapshot` = Ethernet
    // MTU) and the `payload_bytes_eq` prefix matcher are inherited from
    // `CapturedPayloadSnapshot`. §5.1.6 SOMEIP_ETS Method-Response echo
    // conds index the snapshot directly (`captured.payload_snapshot[N]`)
    // or collapse N byte-equality conjuncts into a single
    // `cpp:captured.payload_bytes_eq({0xFE, 0xFF, ...})` call — e.g.
    // ETS_005 (checkByteOrder UInt32 BE sum), ETS_008 (echoCommon
    // Datatypes 27-byte struct), ETS_046/_047/_053 (UTF FIXED 64-byte
    // echo), ETS_041/_050 (UTF DYNAMIC echo, 132 B max). RPC §5.1.5.7
    // setter cases (RPC_11) read `payload_snapshot[0]` to verify the DUT
    // echoed the written UInt8 value. The first payload byte is always
    // `payload_snapshot[0]` (0 when the frame carried no payload), so no
    // dedicated `payload_byte0` slot is needed.

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

    // Length of the entries array in bytes. Per SD TR_SOMEIP §7.3 each entry is 16
    // bytes, so valid values are multiples of 16. Stays 0 when the payload
    // is too short to reach the entries-length field.
    std::uint32_t sd_entries_len = 0;

    // Length of the options array in bytes. Per SD TR_SOMEIP §7.3 the options-length
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

    // SOME/IP-SD Configuration Option (type 0x01) body — the DNS TXT-like sequence of
    // length-prefixed "key[=value]" items, zero-length-terminated (PRS_SOMEIPSD /
    // SWS_SD §7.3). Populated by parseSdOptionsInto from the first type-0x01 option.
    static constexpr std::size_t kMaxSdConfigItems = 8;
    std::uint8_t sd_config_item_count = 0;
    SdConfigItem sd_config_items[kMaxSdConfigItems]{};

    // The first parsed config item matching `key` ("key" exactly, or "key=..."), or
    // nullptr if absent. The single match site the has-key / value-of helpers share.
    const SdConfigItem *sd_config_item_for(std::string_view key) const {
        for (std::uint8_t i = 0; i < sd_config_item_count; ++i) {
            const std::string_view item(reinterpret_cast<const char *>(sd_config_items[i].bytes),
                                        sd_config_items[i].captured);
            if (item == key || (item.size() > key.size() && item.compare(0, key.size(), key) == 0 &&
                                 item[key.size()] == '=')) {
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

    // §5.1.5.3.2 SOMEIPSRV_SD_MESSAGE_02 dynamic instance extraction.
    // The spec body (steps 6-7) extracts instance IDs from a 2-entry
    // OfferService response to Find(instance_id=0xFFFF), then issues
    // follow-up Finds with each extracted instance to assert each one
    // returns a 1-entry OfferService for that instance only. SD_MESSAGE_02
    // trait overrides dispatch to snapshot entries[0..1].instance_id
    // whenever a 2-entry OfferService is observed; the SCXML phase 2/3
    // conds compare incoming 1-entry replies against these slots so the
    // verdict no longer hardcodes `expected.instance_id + 1` (which
    // assumes the tc8-dut sequential allocator). Stays 0 for all other
    // cases.
    std::uint16_t extracted_instance_id_1 = 0;
    std::uint16_t extracted_instance_id_2 = 0;

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

    // Returns true when this frame is the DUT's OfferService for
    // `want_service_id`: an SD message (header service_id == 0xFFFF) whose
    // first entry is an OfferService (type 0x01) advertising that service.
    // This is the canonical proof-of-life — only the DUT emits OfferService
    // for its own service, never the tester (which sends FindService 0x00 /
    // SubscribeEventgroup 0x06) — so the sound 4-value field-check templates
    // and SOMEIP_ETS_152 use it as the Phase 1 liveness gate. Single source
    // of truth for that predicate so the gate cannot drift across templates.
    bool is_offer_service_for(std::uint16_t want_service_id) const {
        return service_id == 0xFFFF && sd_entry_count >= 1 &&
               sd_entries[0].type == 0x01 &&
               sd_entries[0].service_id == want_service_id;
    }

    // Returns true when this frame is the DUT's client-role Method Request to
    // `want_service_id` / `want_method_id`: a Request (0x00) or RequestNoReturn
    // (0x01) carrying that service+method. In the SOMEIPCLT topology the DUT is
    // the client, so this is the canonical recognizer for "the DUT called our
    // offered service" — the client-role mirror of is_offer_service_for. For a
    // Request (0x00) the reply target is this frame's src_ip / src_port (feed
    // emitMethodReply); a RequestNoReturn (0x01) gets NO reply per
    // PRS_SOMEIP_00701, so do not feed those to emitMethodReply. Single source
    // of truth so CLT_RPC cases do not re-spell the type check.
    bool is_method_request_for(std::uint16_t want_service_id, std::uint16_t want_method_id) const {
        return service_id == want_service_id && method_id == want_method_id &&
               (message_type == static_cast<std::uint8_t>(someip::MessageType::REQUEST) ||
                message_type == static_cast<std::uint8_t>(someip::MessageType::REQUEST_NO_RETURN));
    }

    // --- SOMEIPCLT DUT client-role SD recognizers ---
    //
    // In the CLT topology the DUT is the client: it emits FindService (0x00),
    // SubscribeEventgroup (0x06, ttl > 0) and StopSubscribeEventgroup (0x06,
    // ttl == 0 — same entry type, TTL discriminates). These mirror
    // is_offer_service_for for the inbound DUT direction so a CLT case answers
    // (emitSubscribeEventgroupAck / emitMethodReply) without re-spelling the
    // entry-type + id checks. The reply target is this frame's src_ip / src_port.
    // `want_service_id == 0xFFFF` matches any service (a wildcard FindService).
    // Like is_offer_service_for, these inspect sd_entries[0] only (the DUT's
    // client-role SD messages carry the relevant entry first); a future case that
    // needs a non-first entry would match over sd_entries[0..sd_entry_count).

    // DUT FindService for `want_service_id` (first entry type 0x00).
    bool is_find_service_from_dut(std::uint16_t want_service_id) const {
        return service_id == 0xFFFF && sd_entry_count >= 1 &&
               sd_entries[0].type == 0x00 &&
               (want_service_id == 0xFFFF || sd_entries[0].service_id == want_service_id);
    }

    // DUT SubscribeEventgroup for `(want_service_id, want_eventgroup_id)` with a
    // live TTL (> 0). A StopSubscribe (TTL 0) returns false here — use
    // is_stop_subscribe for that.
    bool is_subscribe_for(std::uint16_t want_service_id, std::uint16_t want_eventgroup_id) const {
        return service_id == 0xFFFF && sd_entry_count >= 1 &&
               sd_entries[0].type == 0x06 && sd_entries[0].ttl > 0 &&
               sd_entries[0].service_id == want_service_id &&
               sd_entries[0].eventgroup_id == want_eventgroup_id;
    }

    // DUT StopSubscribeEventgroup for `(want_service_id, want_eventgroup_id)` —
    // a SubscribeEventgroup entry (type 0x06) whose TTL is 0 (TR_SOMEIP §7.4.2).
    bool is_stop_subscribe(std::uint16_t want_service_id, std::uint16_t want_eventgroup_id) const {
        return service_id == 0xFFFF && sd_entry_count >= 1 &&
               sd_entries[0].type == 0x06 && sd_entries[0].ttl == 0 &&
               sd_entries[0].service_id == want_service_id &&
               sd_entries[0].eventgroup_id == want_eventgroup_id;
    }

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

// Decode the Options Array (TR_SOMEIP §7.3, after the Entries Array). Caller passes
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
    c.datagram_msg_index = f.datagram_msg_index;
    c.datagram_msg_count = f.datagram_msg_count;
    // Shared bounded copy of the leading payload bytes from the base;
    // `payload_snapshot[0]` subsumes the former `payload_byte0` slot.
    c.fillPayloadSnapshot(f.payload_data, f.payload_len);
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
    // SOME/IP-TP: the capture context is reused across frames, so reset per frame, then
    // populate from the TP header only when the TP-Flag is set AND the header parses, so
    // is_tp never reports true on a stale prior frame or a frame too short to carry one.
    // someiptp::parseTpHeader owns the 4-byte header layout; the rest is the payload.
    c.is_tp = false;
    c.tp_offset = 0;
    c.tp_more_segments = false;
    c.tp_segment_len = 0;
    if ((f.message_type & someiptp::kMessageTypeTpFlag) != 0) {
        someiptp::TpSegmentHeader tph;
        if (someiptp::parseTpHeader(f.payload_data, f.payload_len, tph)) {
            c.is_tp = true;
            c.tp_offset = static_cast<std::uint32_t>(tph.offset);
            c.tp_more_segments = tph.more_segments;
            c.tp_segment_len = static_cast<std::uint32_t>(f.payload_len - someiptp::kTpHeaderLen);
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
// without re-decoding the raw bytes; the entry field layout (offsets, widths,
// and the bit slices) is owned by someip_sd_wire.def and expanded here, so
// the C++ decoder is a direct consumer of the SSOT, not a hand-mirror of it.
// The Python site mirror derives from the same .def — see docs/tech-debt.md
// TD-01.
inline void decodeSdEntry(SdEntry &dst, const std::uint8_t *src) {
#define TC8_SD_ENTRY_FIELD(group, member, off, size, shift, mask) \
    dst.member = static_cast<decltype(dst.member)>(              \
        ::tc8::sd_wire::readBe(src + (off), (size), (shift), (mask)));
#include "someip_sd_wire.def"
#undef TC8_SD_ENTRY_FIELD
}

// Parse the SD payload layout (TR_SOMEIP §7.3): 4-byte header (Flags + Reserved),
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
#define TC8_SD_HEADER_FIELD(member, off, size, shift, mask) \
    c.member = static_cast<decltype(c.member)>(            \
        ::tc8::sd_wire::readBe(payload + (off), (size), (shift), (mask)));
#include "someip_sd_wire.def"
#undef TC8_SD_HEADER_FIELD

    if (payload_len < 8) {
        return;
    }
#define TC8_SD_ENTRIESLEN_FIELD(member, off, size, shift, mask) \
    c.member = static_cast<decltype(c.member)>(                \
        ::tc8::sd_wire::readBe(payload + (off), (size), (shift), (mask)));
#include "someip_sd_wire.def"
#undef TC8_SD_ENTRIESLEN_FIELD

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
    bool config_seen = false;
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
            // Field layout owned by someip_sd_wire.def (TD-01 SSOT). The
            // TC8_SD_OPTION_ADDR row memcpy's the 4 wire bytes, preserving
            // network byte order — the resulting `ipv4` uint32 compares
            // equal to expected.* values produced by inet_pton (which
            // stores `addr.s_addr` in NBO).
#define TC8_SD_OPTION_FIELD(member, off, size, shift, mask) \
            dst.member = static_cast<decltype(dst.member)>( \
                ::tc8::sd_wire::readBe(o + (off), (size), (shift), (mask)));
#define TC8_SD_OPTION_ADDR(member, off) std::memcpy(&dst.member, o + (off), 4);
#include "someip_sd_wire.def"
#undef TC8_SD_OPTION_FIELD
#undef TC8_SD_OPTION_ADDR
        }

        // Configuration Option (type 0x01): a Reserved byte then the DNS TXT-like
        // config string — length-prefixed "key[=value]" items, zero-length-terminated
        // (PRS_SOMEIPSD / SWS_SD §7.3). Parse the first such option's items.
        if (opt_type == sd_option_type::kConfiguration && !config_seen && opt_len >= 1) {
            config_seen = true;
            dst.reserved1 = o[3];
            const std::uint8_t *cs = o + 4;           // after Length(2) + Type(1) + Reserved(1)
            const std::size_t cs_len = opt_len - 1u;  // option body minus the Reserved byte
            std::size_t p = 0;
            std::uint8_t items = 0;
            while (p < cs_len && items < SomeIpCaptured::kMaxSdConfigItems) {
                const std::uint8_t item_len = cs[p];
                if (item_len == 0) {
                    break;  // zero-length byte terminates the sequence
                }
                ++p;
                if (p + item_len > cs_len) {
                    break;  // item runs past the option body — truncated
                }
                SdConfigItem &item = c.sd_config_items[items];
                item.len = item_len;
                item.captured = static_cast<std::uint8_t>(
                    item_len < kMaxSdConfigItemLen ? item_len : kMaxSdConfigItemLen);
                std::memcpy(item.bytes, cs + p, item.captured);
                p += item_len;
                ++items;
            }
            c.sd_config_item_count = items;
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

// Trace-recording hook (Evidence Export). See arp_captured.h for the
// design overview; this overload exposes the SOME/IP cond-gating subset
// (service/method/client/session ids + msg_type + return_code +
// transport 4-tuple) without enumerating the bulky SD entry/option
// arrays — those rarely drive verdict-decider disclosure.
inline void appendCapturedJson(std::string &out, const SomeIpCaptured &c) {
    out.append("{");
    ::tc8::sce::appendUintJson(out, "\"service_id\":", c.service_id);
    ::tc8::sce::appendUintJson(out, ",\"method_id\":", c.method_id);
    ::tc8::sce::appendUintJson(out, ",\"client_id\":", c.client_id);
    ::tc8::sce::appendUintJson(out, ",\"session_id\":", c.session_id);
    ::tc8::sce::appendUintJson(out, ",\"message_type\":", c.message_type);
    ::tc8::sce::appendUintJson(out, ",\"return_code\":", c.return_code);
    ::tc8::sce::appendUintJson(out, ",\"payload_len\":", c.payload_len);
    out.append(",");
    ::tc8::sce::appendL3EndpointsJson(out, c);
    ::tc8::sce::appendL4PortsJson(out, c);
    if (c.sd_entry_count != 0) {
        ::tc8::sce::appendUintJson(out, ",\"sd_entry_count\":", c.sd_entry_count);
        ::tc8::sce::appendUintJson(out, ",\"sd_option_count\":", c.sd_option_count);
    }
    ::tc8::sce::appendTimingJson(out, c);
    out.append("}");
}

}  // namespace tc8
