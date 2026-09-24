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
// The payload the case names, "DUPLICATE FRAGMENTS TEST", is 24 chars.
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

// The Echo data a reassembled reply must carry, as the view
// `Icmpv4Captured::payload_equals` takes. One name per case for its pass guard
// and its `_NEG` data variant, so neither spells the cast in SCXML.
inline std::string_view reassembly04EchoData() {
    return {reinterpret_cast<const char*>(kReassembly04EchoPayload.data()),
            kReassembly04EchoPayload.size()};
}

// The 2-fragment cases (_10 / _11 / _12) carry the FRAGMENTS_01 body, so their
// `_NEG` data variants name fragmentsEchoData() directly.
inline std::string_view reassembly11EchoData() {
    return ::tc8::sce::ipv4::fragments::fragmentsEchoData();
}

inline std::string_view reassembly13EchoData() {
    return {reinterpret_cast<const char*>(kReassembly13EchoPayload.data()),
            kReassembly13EchoPayload.size()};
}

// REASSEMBLY_11's two fragments: kReassembly11IpId and kReassemblyLargeTtl
// on both halves, the FRAGMENTS_01 16 B body split 8/8. The one builder for
// the positive (which sends frag 0 and schedules frag 1 past the reassembly
// timeout) and its `_NEG` siblings (which send both back to back, so a
// conformant DUT reassembles before any timer can expire). Sharing it keeps
// the frames a sibling faults identical to the positive's.
inline ::tc8::sce::ipv4::fragments::FragmentPair buildReassembly11FragmentPair(
    const ::tc8::TestConfig& cfg) {
    ::tc8::sce::ipv4::fragments::FragmentPairParams params{};
    params.ip_id_frag0 = kReassembly11IpId;
    params.ip_id_frag1 = kReassembly11IpId;
    params.ttl_frag0   = kReassemblyLargeTtl;
    params.ttl_frag1   = kReassemblyLargeTtl;
    return ::tc8::sce::ipv4::fragments::buildFragmentPair(cfg, cfg.arp.dut_iface_mac, params);
}

// Send REASSEMBLY_11's pair back to back (no timer-extension premise). The
// `_NEG` siblings' stimulus: a conformant DUT reassembles it and replies, which
// is the frame their egress faults corrupt and their drop fault prevents.
inline void emitReassembly11PairBackToBack(const ::tc8::TestConfig& cfg, std::string_view iface) {
    const auto pair = buildReassembly11FragmentPair(cfg);
    ::tc8::stimulus::IpBootTiming t0{};
    t0.initial_wait = std::chrono::milliseconds{200};
    ::tc8::stimulus::emitIpv4Frame(iface, pair.frag0_spec, pair.frag0_payload, t0);
    ::tc8::stimulus::IpBootTiming t1{};
    t1.initial_wait = std::chrono::milliseconds{0};
    ::tc8::stimulus::emitIpv4Frame(iface, pair.frag1_spec, pair.frag1_payload, t1);
}

// The stimuli of REASSEMBLY_04 / _10 / _12 below are each the ONE emitter for a
// positive and its `_NEG`, so the frames a sibling faults are the positive's own
// (the reason buildReassembly11FragmentPair is shared above).

// REASSEMBLY_04: the 32 B Echo Request body in four 8 B fragments, sent in the
// spec's wire order frag 0 -> 2 -> 1 -> 3 (out of order, none missing).
inline void emitReassembly04Fragments(const ::tc8::TestConfig& cfg, std::string_view iface) {
    const auto body = buildReassembly32BEchoBody();
    const std::vector<std::uint8_t> frag0_payload(body.begin() +  0, body.begin() +  8);
    const std::vector<std::uint8_t> frag1_payload(body.begin() +  8, body.begin() + 16);
    const std::vector<std::uint8_t> frag2_payload(body.begin() + 16, body.begin() + 24);
    const std::vector<std::uint8_t> frag3_payload(body.begin() + 24, body.begin() + 32);
    const auto mac = cfg.arp.dut_iface_mac;
    emitIpv4Fragment(iface, cfg, mac, kReassembly04IpId, /*offset=*/0, /*MF=*/true,  /*ttl=*/64, frag0_payload);
    emitIpv4Fragment(iface, cfg, mac, kReassembly04IpId, /*offset=*/2, /*MF=*/true,  /*ttl=*/64, frag2_payload);
    emitIpv4Fragment(iface, cfg, mac, kReassembly04IpId, /*offset=*/1, /*MF=*/true,  /*ttl=*/64, frag1_payload);
    emitIpv4Fragment(iface, cfg, mac, kReassembly04IpId, /*offset=*/3, /*MF=*/false, /*ttl=*/64, frag3_payload);
}

// REASSEMBLY_10 phase A: a pair on kReassembly10IpIdPhaseA with a 1 s wait,
// inside the (toggled 2 s) reassembly timer.
inline void emitReassembly10PhaseA(const ::tc8::TestConfig& cfg, std::string_view iface) {
    ::tc8::sce::ipv4::fragments::FragmentPairParams phase_a{};
    phase_a.ip_id_frag0 = kReassembly10IpIdPhaseA;
    phase_a.ip_id_frag1 = kReassembly10IpIdPhaseA;
    ::tc8::sce::ipv4::fragments::emitFragmentPair(
        iface, cfg, cfg.arp.dut_iface_mac, phase_a,
        /*initial_wait=*/std::chrono::milliseconds{200},
        /*inter_frag_wait=*/std::chrono::milliseconds{1000},
        /*post_send_wait=*/std::chrono::milliseconds{200});
}

// REASSEMBLY_10 phase B: a pair on kReassembly10IpIdPhaseB with a 3 s wait,
// past the timer, so frag 1' arrives after the bucket was freed.
inline void emitReassembly10PhaseB(const ::tc8::TestConfig& cfg, std::string_view iface) {
    ::tc8::sce::ipv4::fragments::FragmentPairParams phase_b{};
    phase_b.ip_id_frag0 = kReassembly10IpIdPhaseB;
    phase_b.ip_id_frag1 = kReassembly10IpIdPhaseB;
    ::tc8::sce::ipv4::fragments::emitFragmentPair(
        iface, cfg, cfg.arp.dut_iface_mac, phase_b,
        /*initial_wait=*/std::chrono::milliseconds{0},
        /*inter_frag_wait=*/std::chrono::milliseconds{3000},
        /*post_send_wait=*/std::chrono::milliseconds{200});
}

// REASSEMBLY_12: a Low-TTL pair on kReassembly12IpId with a 1 s wait.
inline void emitReassembly12Pair(const ::tc8::TestConfig& cfg, std::string_view iface) {
    ::tc8::sce::ipv4::fragments::FragmentPairParams params{};
    params.ip_id_frag0 = kReassembly12IpId;
    params.ip_id_frag1 = kReassembly12IpId;
    params.ttl_frag0   = kReassemblyLowTtl;
    params.ttl_frag1   = kReassemblyLowTtl;
    ::tc8::sce::ipv4::fragments::emitFragmentPair(
        iface, cfg, cfg.arp.dut_iface_mac, params,
        /*initial_wait=*/std::chrono::milliseconds{200},
        /*inter_frag_wait=*/std::chrono::milliseconds{1000},
        /*post_send_wait=*/std::chrono::milliseconds{0});
}

// REASSEMBLY_13's fragments, in 8-octet offsets over a 35 B Echo Request body
// (8 B ICMP header + 27 B kReassembly13EchoPayload, checksum computed once
// over the post-resolution region):
//   head          offset 0, MF, body[0..15]
//   wrong_overlap offset 2, MF, 24 B kReassembly13WrongFragPayload
//   right_overlap offset 2, MF, body[16..23] (the most recent data)
//   tail          offset 3,     body[24..34]
// head + right_overlap + tail alone is the same datagram with no overlap.
struct Reassembly13Fragments {
    std::vector<std::uint8_t> head;
    std::vector<std::uint8_t> wrong_overlap;
    std::vector<std::uint8_t> right_overlap;
    std::vector<std::uint8_t> tail;
};

inline constexpr std::uint16_t kReassembly13HeadOffset    = 0;
inline constexpr std::uint16_t kReassembly13OverlapOffset = 2;
inline constexpr std::uint16_t kReassembly13TailOffset    = 3;

inline Reassembly13Fragments buildReassembly13Fragments() {
    const auto body = ::tc8::wire::buildIcmpEchoRequestBody(
        ::tc8::stimulus::kIcmpEchoId,
        ::tc8::stimulus::kIcmpEchoSeq,
        kReassembly13EchoPayload.data(),
        static_cast<std::uint32_t>(kReassembly13EchoPayload.size()));
    Reassembly13Fragments f;
    f.head.assign(body.begin(), body.begin() + 16);
    f.wrong_overlap.assign(kReassembly13WrongFragPayload.begin(),
                           kReassembly13WrongFragPayload.end());
    f.right_overlap.assign(body.begin() + 16, body.begin() + 24);
    f.tail.assign(body.begin() + 24, body.end());
    return f;
}

// Send REASSEMBLY_13's datagram WITHOUT the overlapping wrong fragment: head,
// right_overlap, tail. The `_NEG` siblings' stimulus — neither reference DUT
// resolves an overlap (docs/tech-debt.md TD-33; lwIP's chain check needs exact
// contiguity), so only this contiguous form gives a conformant DUT a reply
// for the faults to act on. The guards read the reply frame alone, and its
// id, seq and 27 B data are the ones the positive's reply would carry. Same
// pacing as the positive: each fragment after the default 200 ms wait.
inline void emitReassembly13WithoutOverlap(const ::tc8::TestConfig& cfg, std::string_view iface) {
    const auto f = buildReassembly13Fragments();
    emitIpv4Fragment(iface, cfg, cfg.arp.dut_iface_mac, kReassembly13IpId,
                     kReassembly13HeadOffset, /*more_fragments=*/true, /*ttl=*/64, f.head);
    emitIpv4Fragment(iface, cfg, cfg.arp.dut_iface_mac, kReassembly13IpId,
                     kReassembly13OverlapOffset, /*more_fragments=*/true, /*ttl=*/64, f.right_overlap);
    emitIpv4Fragment(iface, cfg, cfg.arp.dut_iface_mac, kReassembly13IpId,
                     kReassembly13TailOffset, /*more_fragments=*/false, /*ttl=*/64, f.tail);
}

}  // namespace tc8::sce::ipv4::reassembly
