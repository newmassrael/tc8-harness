#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/protocol_frames/icmpv4_frame.h"

#include "sce_integration/captured_frame_timing.h"
#include "sce_integration/captured_payload_snapshot.h"
#include "sce_integration/captured_trace.h"
#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying fields parsed from an observed ICMPv4
// frame. Matching SCXML declaration:
//   <sce:context id="captured" cpp:type="tc8::Icmpv4Captured"
//                cpp:include="sce_integration/icmpv4_captured.h"/>
//
// Fields mirror `tc8::Icmpv4Frame` with Echo-oriented decoding: the
// 32-bit `rest_of_header` is pre-split into `echo_id` (hi 16) and
// `echo_seq` (lo 16) so SCXML guards compare named fields without extra
// shift/mask expressions. Non-Echo ICMP types reuse the same slots with
// different semantics (next-hop MTU, parameter pointer, ...); the pilot
// only covers Echo so that reinterpretation is deferred.
//
// The inherited `payload_snapshot` captures up to `kMaxPayloadSnapshot`
// bytes of the ICMP payload for field-level byte comparison (§4.3.3.2
// TYPE_08 "Echo Reply data field"). The underlying
// `Icmpv4Frame::payload_data` pointer is non-owning and valid only
// during `dispatch()`, so the copy is necessary — SCXML guards can
// evaluate at any later tick.
struct Icmpv4Captured : CapturedPayloadSnapshot, CapturedFrameTiming {
    std::uint32_t src_ip    = 0;  // network byte order
    std::uint32_t dst_ip    = 0;
    std::uint8_t  type      = 0;  // RFC 792: 0 = Echo Reply, 8 = Echo Request, ...
    std::uint8_t  code      = 0;
    std::uint16_t checksum  = 0;
    std::uint16_t echo_id   = 0;  // rest_of_header[31..16] for Echo/EchoReply
    std::uint16_t echo_seq  = 0;  // rest_of_header[15..0]

    // Parameter Problem (type=12) Pointer field per RFC 792 — the
    // byte offset (from the start of the offending datagram, 1-
    // indexed) of the malformed header byte. Occupies bits [31..24]
    // of `rest_of_header`, disjoint from `echo_id`/`echo_seq` which
    // reinterpret the same 32-bit slot for Echo/EchoReply. §4.3.3.1
    // ERROR_02 gates its pass transition on `icmp_pointer == 22`
    // (IP header length 20 + offset of the option's pointer byte
    // within the Timestamp option = 22 in 1-indexed-from-datagram-
    // start coordinates).
    std::uint8_t  icmp_pointer = 0;
    std::uint32_t payload_len = 0;  // full ICMP payload length (wire-side)

    // RFC 792 p17 ICMP Timestamp / Timestamp Reply (type=13/14) body
    // slots, decoded from the wire when type matches. Stored in host
    // byte order so SCXML guards compare directly against host-order
    // literals (e.g. `::tc8::stimulus::kIcmpTimestampOriginate`). For
    // any other ICMP type these stay at 0 — the dissector narrows the
    // copy on type so non-Timestamp messages don't pollute these
    // slots with reinterpretations of the same byte region (e.g.
    // Address Mask).
    //
    // §4.3.3.2 TYPE_11 pass guard: `originate_timestamp == originate
    // literal AND receive_timestamp != 0 AND transmit_timestamp != 0`
    // (RFC 792 p17 contract: the Reply echoes Originate verbatim and
    // fills Receive / Transmit with the responder's clock readings).
    std::uint32_t originate_timestamp = 0;
    std::uint32_t receive_timestamp   = 0;
    std::uint32_t transmit_timestamp  = 0;

    // The payload snapshot (`payload_snapshot` / `payload_snapshot_len`,
    // capacity `kMaxPayloadSnapshot` = Ethernet MTU) is inherited from
    // `CapturedPayloadSnapshot`. It covers the §4.4.4.1 IPv4_HEADER_05
    // spec literal — 548 B ICMP Data inside the 576 B minimum IP
    // datagram (RFC 791 §3.1) — and the §4.3.3.2 TYPE_08 27 B literal
    // with margin.

    // Inter-frame timing surface (`observed_ts_us` / `prev_observed_ts_us`
    // / `frame_delta_us()`) is inherited from `CapturedFrameTiming`.
    // ICMPv4 cases dispatch via `dispatchIcmpv4Frame`, which auto-
    // snapshots prev on fired-transition frames; first-transition guards
    // must NOT depend on `frame_delta_us()`.

    // Byte comparison of the payload snapshot is inherited from
    // `CapturedPayloadSnapshot`: `payload_equals(string_view)` for the
    // §4.3.3.2 TYPE_08 verbatim Echo-Reply check, and
    // `payload_matches_index_pattern(len)` for the §4.4.4.1
    // IPv4_HEADER_05 `byte[i] = i & 0xFF` cycling-pattern echo.
};

// §4.3.3.2 ICMPv4_TYPE_08 Echo Request/Reply data field — the spec
// literal the tester sends and the DUT must echo back verbatim. Exposed
// as a constexpr so both the stimulus builder and the SCXML guard
// reference one source of truth. Size is `sizeof - 1` because the
// trailing NUL is not part of the wire payload.
inline constexpr std::string_view kIcmpv4EchoPayloadType08{
    "ECU NETWORK VALIDATION TEST"};

// ADL hook called by `TestRunner<SM>` at construction. No-op for captured
// because captured fields get populated from wire frames, not from CLI
// configuration; the overload exists so the uniform `applyTestConfig(c, cfg)`
// call in TestRunner compiles for every Named Context type.
inline void applyTestConfig(Icmpv4Captured & /*c*/, const TestConfig & /*cfg*/) {
    // captured-from-wire fields have no CLI-driven initial values.
}

inline void fillIcmpv4CapturedFromFrame(Icmpv4Captured &c, const Icmpv4Frame &f) {
    c.src_ip     = f.src_ip;
    c.dst_ip     = f.dst_ip;
    c.type       = f.type;
    c.code       = f.code;
    c.checksum   = f.checksum;
    c.echo_id    = static_cast<std::uint16_t>((f.rest_of_header >> 16) & 0xFFFFU);
    c.echo_seq   = static_cast<std::uint16_t>(f.rest_of_header & 0xFFFFU);
    // Parameter Problem Pointer lives in byte[0] of the 4-byte rest-
    // of-header slot. `rest_of_header` is a uint32 whose MSB is byte 0
    // in big-endian wire order (same convention as `echo_id` above),
    // so bits [31..24] extract the Pointer byte.
    c.icmp_pointer = static_cast<std::uint8_t>((f.rest_of_header >> 24) & 0xFFU);
    c.payload_len = f.payload_len;
    // Timestamp slots — dissector copies from libtins's typed accessors
    // only for type=13/14, so for any other type these remain at 0 and
    // the SCXML guards behave as if the fields didn't exist for that
    // capture. Forward verbatim — endianness conversion already done
    // by libtins.
    c.originate_timestamp = f.originate_timestamp;
    c.receive_timestamp   = f.receive_timestamp;
    c.transmit_timestamp  = f.transmit_timestamp;

    // Shared bounded copy of the leading payload bytes from the base.
    c.fillPayloadSnapshot(f.payload_data, f.payload_len);
    c.observed_ts_us = f.observed_ts_us;
}

// Trace-recording hook (Evidence Export). See arp_captured.h for the
// design overview; this overload exposes the ICMPv4 cond-gating subset
// (type/code + 4-tuple + Echo id/seq + Parameter Problem pointer).
inline void appendCapturedJson(std::string &out, const Icmpv4Captured &c) {
    char buf[64];
    out.append("{\"type\":");
    std::snprintf(buf, sizeof(buf), "%u", c.type); out.append(buf);
    out.append(",\"code\":");
    std::snprintf(buf, sizeof(buf), "%u", c.code); out.append(buf);
    out.append(",\"src_ip\":");
    ::tc8::sce::appendIpv4Json(out, c.src_ip);
    out.append(",\"dst_ip\":");
    ::tc8::sce::appendIpv4Json(out, c.dst_ip);
    if (c.echo_id != 0 || c.echo_seq != 0) {
        out.append(",\"echo_id\":");
        std::snprintf(buf, sizeof(buf), "%u", c.echo_id); out.append(buf);
        out.append(",\"echo_seq\":");
        std::snprintf(buf, sizeof(buf), "%u", c.echo_seq); out.append(buf);
    }
    if (c.icmp_pointer != 0) {
        out.append(",\"icmp_pointer\":");
        std::snprintf(buf, sizeof(buf), "%u", c.icmp_pointer); out.append(buf);
    }
    out.append(",\"payload_len\":");
    std::snprintf(buf, sizeof(buf), "%u", c.payload_len); out.append(buf);
    out.append("}");
}

}  // namespace tc8
