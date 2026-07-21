#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <vector>

#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/test_config.h"
#include "stimulus/icmpv4_builder.h"
#include "stimulus/ipv4_frame_builder.h"
#include "tc8/wire/icmp_echo.h"

namespace tc8::sce::ipv4::reassembly {

// §4.4.4.7 IPv4 REASSEMBLY shared payload constants. Reuse the
// FRAGMENTS_01 8-byte pattern for 2-fragment (16 B body) cases — the
// reassembled body is identical to FRAGMENTS_01 (8 B header + 8 B
// payload), so REASSEMBLY_10/_11/_12 inherit the FRAGMENTS pass-criterion
// shape via the same `kFragmentsEchoPayload` constant referenced on
// the SCXML side. Defined in `ipv4_fragments_common.h`.

// REASSEMBLY_04 reassembles a 4-fragment Echo Request: 8 B ICMP header
// + 24 B data, split into 4 chunks of 8 B each. The 24 B payload is a
// distinct constant so smoke-test grep can disambiguate REASSEMBLY_04
// passes from FRAGMENTS_01-style 8 B passes. Arbitrary non-zero bytes;
// non-repeating so a wrongly-ordered reassembly produces a different
// payload that the SCXML's `payload_equals` guard rejects.
inline constexpr std::array<std::uint8_t, 24> kReassembly04EchoPayload{
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7};

// REASSEMBLY_13 spec literal — 27-byte ICMP Echo Request "Data field"
// the DUT's reassembled Echo Reply must mirror after most-recent-wins
// overlap resolution per RFC 791 §3.2. Used by both the wire-level
// body builder (frags 0/2/3 carry slices of this) and the SCXML pass
// guard (payload_equals).
inline constexpr std::array<std::uint8_t, 27> kReassembly13EchoPayload{
    'E','C','U',' ','N','E','T','W','O','R','K',' ',
    'V','A','L','I','D','A','T','I','O','N',' ',
    'T','E','S','T'};

// REASSEMBLY_13 step-4 wrong-data fragment payload — 24 B at
// offset=2 (8-octet units → byte 16 of reassembled body, covering
// bytes 16..39 of the bucket). frag 2 (step 7) is meant to overwrite
// bytes 16..23 with the correct data per RFC 791's most-recent-wins.
// Spec literal "DUPLICATE FRAGMENTS TEST" pads to 24 chars exactly.
inline constexpr std::array<std::uint8_t, 24> kReassembly13WrongFragPayload{
    'D','U','P','L','I','C','A','T','E',' ',
    'F','R','A','G','M','E','N','T','S',' ','T','E','S','T'};

// IP Identification literals per case so cross-case bucket reuse never
// occurs. Each case picks its own non-zero value distinct from
// FRAGMENTS' 0xF001/0xF002. Per-phase IDs (REASSEMBLY_10) are
// adjacent so the smoke log narrative is readable.
inline constexpr std::uint16_t kReassembly04IpId       = 0xF010;
inline constexpr std::uint16_t kReassembly06IpId       = 0xF011;
inline constexpr std::uint16_t kReassembly07IpId       = 0xF012;
inline constexpr std::uint16_t kReassembly09IpId       = 0xF013;
inline constexpr std::uint16_t kReassembly10IpIdPhaseA = 0xF014;
inline constexpr std::uint16_t kReassembly10IpIdPhaseB = 0xF015;
inline constexpr std::uint16_t kReassembly11IpId       = 0xF016;
inline constexpr std::uint16_t kReassembly12IpId       = 0xF017;
inline constexpr std::uint16_t kReassembly13IpId       = 0xF018;

// §4.4.4.7 REASSEMBLY_11/12 TTL knobs. Linux's local-delivery path
// does not decrement TTL on locally-destined fragments, so any value
// > 0 lands in the reassembly bucket equivalently. The Large/Low
// distinction is part of the spec's TTL-extends-timer narrative; on
// Linux the static `net.ipv4.ipfrag_time` ignores TTL entirely (see
// the case-level Linux-deviation note). LowTTL is held at 2 (not 1)
// so any future netns hop that does decrement does not zero out.
inline constexpr std::uint8_t kReassemblyLargeTtl = 0xFF;  // 255
inline constexpr std::uint8_t kReassemblyLowTtl   = 2;

// Emit a single IPv4 fragment with explicit per-frag knobs. The body
// `payload` is the IPv4-payload byte slice (e.g. partial ICMP body)
// that goes after the IPv4 header on the wire — for fragment 0 of an
// Echo Request that would be the first 8 B of the ICMP body (header);
// for offset>0 fragments it is the corresponding body slice. The
// caller builds the full ICMP body once with
// `buildIcmpEchoRequestBody` and slices it; the reassembled body the
// DUT sees has a single valid checksum because the slice covers the
// region the checksum was computed over.
//
// `more_fragments` is the wire MF flag; `fragment_offset` is in
// 8-octet units (matches the IP header field directly). `timing`
// gates initial/post-send waits — `IpBootTiming{}` is back-to-back
// emit; non-zero `initial_wait` defers, non-zero `post_send_wait`
// blocks the stimulus thread for inter-frag pacing.
inline int emitIpv4Fragment(std::string_view iface,
                            const ::tc8::TestConfig& cfg,
                            const std::array<std::uint8_t, 6>& dst_mac,
                            std::uint16_t ip_id,
                            std::uint16_t fragment_offset,
                            bool more_fragments,
                            std::uint8_t ttl,
                            const std::vector<std::uint8_t>& payload,
                            ::tc8::stimulus::IpBootTiming timing = {}) {
    ::tc8::stimulus::Ipv4FrameSpec spec{};
    spec.dst_mac         = dst_mac;
    spec.src_ip          = cfg.icmpv4.tester_ip;
    spec.dst_ip          = cfg.icmpv4.dut_iface_ip;
    spec.ip_id           = ip_id;
    spec.ttl             = ttl;
    spec.ip_protocol     = ::tc8::stimulus::kIpProtoIcmp;
    spec.more_fragments  = more_fragments;
    spec.fragment_offset = fragment_offset;
    return ::tc8::stimulus::emitIpv4Frame(iface, spec, payload, timing);
}

// Build the full 16 B Echo Request body for 2-fragment REASSEMBLY
// cases (_06/_07/_09) — 8 B ICMP header + 8 B `kFragmentsEchoPayload`,
// identical shape to FRAGMENTS_01. Single source of truth for the
// checksum; per-case stimulus slices it as needed.
//
// `_06/_07` exercise absence: their reassembled body is never seen by
// the DUT (bucket has no offset=0 head, or has a gap), so the
// checksum doesn't matter on-wire — but building a valid body keeps
// the wire frames conformant. `_09` likewise: DUT bucket sits with
// frag 0 (offset=0, MF=1) waiting for offset=1 that never arrives.
inline std::vector<std::uint8_t> buildReassembly16BEchoBody() {
    return ::tc8::wire::buildIcmpEchoRequestBody(
        ::tc8::stimulus::kIcmpEchoId,
        ::tc8::stimulus::kIcmpEchoSeq,
        ::tc8::sce::ipv4::fragments::kFragmentsEchoPayload.data(),
        static_cast<std::uint32_t>(::tc8::sce::ipv4::fragments::kFragmentsEchoPayload.size()));
}

// Build the full 32 B Echo Request body for 4-fragment REASSEMBLY_04 —
// 8 B ICMP header + 24 B `kReassembly04EchoPayload`. Used only by
// REASSEMBLY_04, which slices into 4 chunks of 8 B (offsets 0..3 in
// 8-octet units).
inline std::vector<std::uint8_t> buildReassembly32BEchoBody() {
    return ::tc8::wire::buildIcmpEchoRequestBody(
        ::tc8::stimulus::kIcmpEchoId,
        ::tc8::stimulus::kIcmpEchoSeq,
        kReassembly04EchoPayload.data(),
        static_cast<std::uint32_t>(kReassembly04EchoPayload.size()));
}

}  // namespace tc8::sce::ipv4::reassembly
