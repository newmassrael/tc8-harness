#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

#include "tc8/protocol_frames/someip_frame.h"

#include "autosar/someiptp.h"
#include "someip/protocol.h"
#include "someip/sd_decode.h"  // SdDecoded mixin + SD structs/namespaces + parseSdInto (neutral SD decode leaf)
#include "sce_integration/captured_frame_timing.h"
#include "sce_integration/captured_l3_endpoints.h"
#include "sce_integration/captured_l4_ports.h"
#include "sce_integration/captured_payload_snapshot.h"
#include "sce_integration/captured_trace.h"
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

// The SD wire structs (SdEntry / SdOption / SdConfigItem), the value namespaces
// (sd_option_type / sd_l4_proto / sd_entry_type), the SdDecoded "SD aspect"
// mixin (carrying every sd_* field + the SD-only helper methods), and the parse
// (decodeSdEntry / parseSdInto / peekSdEntry0Type) all live in the neutral leaf
// someip/sd_decode.h. SomeIpCaptured mixes SdDecoded in below, so cond/case
// recognizer code keeps reading `captured.sd_*` unchanged.

struct SomeIpCaptured : CapturedPayloadSnapshot, CapturedFrameTiming,
                        CapturedL3Endpoints, CapturedL4Ports, SdDecoded {
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
    // UDP payload (PRS_SOMEIP permits message concatenation).
    // `datagram_msg_count` stays 0 for SOME/IP-over-
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

    // SD payload fields (sd_flags / sd_reserved / sd_entries_len / sd_options_len,
    // the parsed sd_entries[] / sd_options[] / sd_config_items[] arrays and their
    // counts, cached_offer_endpoint_udp_port, and the SD-only helper methods) are
    // inherited from the SdDecoded mixin (someip/sd_decode.h).

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

    // (cached_offer_endpoint_udp_port, sd_ipv4_endpoint_count / _multicast_count,
    // and the display-only wire totals sd_entry_count_wire /
    // sd_ipv4_endpoint_count_wire are inherited from the SdDecoded mixin.)

    // True when the SOME/IP header is on the Service Discovery channel (Service
    // ID == someip::kSdServiceId). The verdict-path recognizers gate on the
    // Service ID alone — the SD payload has already been parsed under the same
    // gate — so this is the single predicate they share (docs/tech-debt.md TD-07).
    bool headerIsSd() const { return service_id == someip::kSdServiceId; }

    // Returns true when this frame is the DUT's OfferService for
    // `want_service_id`: an SD message (header service_id == 0xFFFF) whose
    // first entry is an OfferService (type 0x01) advertising that service.
    // This is the canonical proof-of-life — only the DUT emits OfferService
    // for its own service, never the tester (which sends FindService 0x00 /
    // SubscribeEventgroup 0x06) — so the sound 4-value field-check templates
    // and SOMEIP_ETS_152 use it as the Phase 1 liveness gate. Single source
    // of truth for that predicate so the gate cannot drift across templates.
    bool is_offer_service_for(std::uint16_t want_service_id) const {
        return headerIsSd() && sd_entry_count >= 1 &&
               sd_entries[0].type == sd_entry_type::kOfferService &&
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
        return headerIsSd() && sd_entry_count >= 1 &&
               sd_entries[0].type == sd_entry_type::kFindService &&
               (want_service_id == 0xFFFF || sd_entries[0].service_id == want_service_id);
    }

    // DUT SubscribeEventgroup for `(want_service_id, want_eventgroup_id)` with a
    // live TTL (> 0). A StopSubscribe (TTL 0) returns false here — use
    // is_stop_subscribe for that.
    bool is_subscribe_for(std::uint16_t want_service_id, std::uint16_t want_eventgroup_id) const {
        return headerIsSd() && sd_entry_count >= 1 &&
               sd_entries[0].type == sd_entry_type::kSubscribeEventgroup &&
               sd_entries[0].ttl > 0 &&
               sd_entries[0].service_id == want_service_id &&
               sd_entries[0].eventgroup_id == want_eventgroup_id;
    }

    // DUT StopSubscribeEventgroup for `(want_service_id, want_eventgroup_id)` —
    // a SubscribeEventgroup entry (type 0x06) whose TTL is 0 (TR_SOMEIP §7.4.2).
    bool is_stop_subscribe(std::uint16_t want_service_id, std::uint16_t want_eventgroup_id) const {
        return headerIsSd() && sd_entry_count >= 1 &&
               sd_entries[0].type == sd_entry_type::kSubscribeEventgroup &&
               sd_entries[0].ttl == 0 &&
               sd_entries[0].service_id == want_service_id &&
               sd_entries[0].eventgroup_id == want_eventgroup_id;
    }

    // (The SD-only option helpers — sd_has_option_with_l4,
    // sd_first_option_with_l4, sd_distinct_endpoint_ports_for_l4 — are inherited
    // from the SdDecoded mixin.)
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

// Shared fill logic for §5.1 cases whose dispatch() copies a SOME/IP
// frame into the captured context. Every SOMEIPSRV case used to carry
// a ~15-line copy block plus a guarded SD parse; centralizing here
// collapses dispatch() bodies to ~5 lines and keeps SD payload parsing
// gated on the SD Service ID (headerIsSd) so non-SD frames never push
// misaligned bytes through parseSdInto.
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
    if (c.headerIsSd()) {
        // Decode the SD payload into the inherited SdDecoded aspect through the
        // neutral leaf (someip/sd_decode.h). The §5.1.5.3.9 cross-phase
        // OfferService endpoint cache (cached_offer_endpoint_udp_port) and the
        // display wire totals are populated inside parseSdInto.
        parseSdInto(c, f.payload_data, f.payload_len);
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
