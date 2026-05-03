#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "tc8/captured_event.h"
#include "sce_integration/icmpv4_captured.h"
#include "sce_integration/test_config.h"
#include "sce_integration/test_runner.h"   // IStimulusScheduler
#include "stimulus/icmpv4_builder.h"       // kIcmpEchoId / kIcmpEchoSeq
#include "stimulus/ipv4_frame_builder.h"

namespace tc8::sce::ipv4::fragments {

using ::tc8::sce::IStimulusScheduler;

// §4.4.4.6 IPV4_FRAGMENTS_01..04 reassembled Echo Request payload —
// the 8 B "Data" region the DUT must echo back verbatim on the
// reassembled reply. FRAGMENTS_01's pass criterion asserts byte-
// equality; FRAGMENTS_02/03/04 phase 2 inherit the same check so
// the reassembled tuple validates end-to-end.
//
// Deterministic literal (not derived from runtime state) so the
// SCXML guard can reference it via the SCE `cpp:` prefix and the
// smoke-test harness stays drift-safe — same single-source pattern
// as `kIcmpv4EchoPayloadType08` / `kTesterInjectedMac`.
inline constexpr std::array<std::uint8_t, 8> kFragmentsEchoPayload{
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

// IP Identification values the FRAGMENTS_02/03/04 compound stimuli
// use to distinguish the two reassembly tuples. `id1` is the
// "matched" tuple that phase 2's retry uses; `id2` is the
// deliberately-different value phase 1 frag 1 uses for FRAGMENTS_02.
// Arbitrary non-zero, non-sequential literals. FRAGMENTS_01 uses
// `id1` for both fragments.
inline constexpr std::uint16_t kFragmentsIpId1 = 0xF001;
inline constexpr std::uint16_t kFragmentsIpId2 = 0xF002;

// Alternate source IP for FRAGMENTS_03 phase 1 frag 1 — "different
// address from host-1" per spec text. Chosen from the same /24 as
// tester/DUT so the DUT's IP layer accepts the fragment without
// foreign-subnet drops; the reassembly-bucket-tuple test invariant
// is what matters, not the rp_filter path.
// 172.16.0.99 in network byte order.
inline constexpr std::uint32_t kFragmentsHost2IpBe = 0x630010AC;

// IANA Protocol byte used for FRAGMENTS_04 phase 1 frag 1 — TCP.
// The DUT's reassembly bucket is keyed on (src, dst, id, protocol),
// so a TCP-protocol frag 1 with an otherwise matching tuple is
// stored in a distinct bucket from frag 0's ICMP bucket and cannot
// reassemble.
inline constexpr std::uint8_t kFragmentsProtocolIcmp = ::tc8::stimulus::kIpProtoIcmp;
inline constexpr std::uint8_t kFragmentsProtocolTcp  = ::tc8::stimulus::kIpProtoTcp;

// Parameters for a single fragment pair — two IP fragments carrying
// the FRAGMENTS reassembled Echo Request body split 8/8. Each field
// independently per-fragment so the compound cases can vary one knob
// while keeping the rest at canonical values. `std::nullopt` for
// `src_ip_*` means "use cfg.icmpv4.tester_ip"; FRAGMENTS_03 sets
// `src_ip_frag1 = kFragmentsHost2IpBe`. Defaults reproduce the
// FRAGMENTS_01 positive path (matching tuple, ICMP protocol, tester
// source on both halves).
//
// `ttl_frag0/1` knobs default to the Ipv4FrameSpec default (64) so
// FRAGMENTS_01..04 callers see no behaviour change. §4.4.4.7
// REASSEMBLY_11/12 vary TTL per fragment (Large/Low TTL pass-through
// — Linux's reassembly bucket carries the wire frame regardless of
// TTL since locally-delivered packets aren't TTL-decremented).
struct FragmentPairParams {
    std::optional<std::uint32_t> src_ip_frag0;
    std::optional<std::uint32_t> src_ip_frag1;
    std::uint16_t ip_id_frag0  = kFragmentsIpId1;
    std::uint16_t ip_id_frag1  = kFragmentsIpId1;
    std::uint8_t  ip_protocol_frag0 = kFragmentsProtocolIcmp;
    std::uint8_t  ip_protocol_frag1 = kFragmentsProtocolIcmp;
    std::uint8_t  ttl_frag0    = 64;
    std::uint8_t  ttl_frag1    = 64;
};

// Builds and emits the two IP fragments carrying a reassembled Echo
// Request. The ICMP body is built ONCE (checksum computed over the
// full 16 B region), then split 8/8 — so a DUT that correctly
// reassembles sees a valid ICMP checksum and emits an Echo Reply
// echoing `kIcmpEchoId` / `kIcmpEchoSeq` / `kFragmentsEchoPayload`.
//
// `initial_wait` defers the first send until the DUT's stack is
// ready (IcmpBootTiming default 200 ms). `inter_frag_wait` pauses
// between the two fragments — 0 ms is the FRAGMENTS_01 default (back-
// to-back send); non-zero useful for debugging. `post_send_wait`
// blocks after the second fragment before returning — unused by
// FRAGMENTS_01, consumed by FRAGMENTS_02/03/04 as the phase-gap
// before the phase-2 retry.
inline int emitFragmentPair(std::string_view iface,
                            const ::tc8::TestConfig& cfg,
                            const std::array<std::uint8_t, 6>& dst_mac,
                            const FragmentPairParams& params,
                            std::chrono::milliseconds initial_wait = std::chrono::milliseconds{200},
                            std::chrono::milliseconds inter_frag_wait = std::chrono::milliseconds{0},
                            std::chrono::milliseconds post_send_wait = std::chrono::milliseconds{0}) {
    const std::uint32_t tester_ip = cfg.icmpv4.tester_ip;
    const std::uint32_t dut_ip    = cfg.icmpv4.dut_iface_ip;

    // Build the full 16 B ICMP body ONCE so the checksum covers the
    // reassembled payload the DUT will see. 8 B ICMP header +
    // kFragmentsEchoPayload (8 B) = 16 B total, split 8/8.
    const auto body = ::tc8::stimulus::buildIcmpEchoRequestBody(
        ::tc8::stimulus::kIcmpEchoId,
        ::tc8::stimulus::kIcmpEchoSeq,
        kFragmentsEchoPayload.data(),
        static_cast<std::uint32_t>(kFragmentsEchoPayload.size()));

    std::vector<std::uint8_t> frag0_payload(body.begin(), body.begin() + 8);
    std::vector<std::uint8_t> frag1_payload(body.begin() + 8, body.end());

    ::tc8::stimulus::Ipv4FrameSpec frag0_spec{};
    frag0_spec.dst_mac        = dst_mac;
    frag0_spec.src_ip         = params.src_ip_frag0.value_or(tester_ip);
    frag0_spec.dst_ip         = dut_ip;
    frag0_spec.ip_id          = params.ip_id_frag0;
    frag0_spec.ip_protocol    = params.ip_protocol_frag0;
    frag0_spec.ttl            = params.ttl_frag0;
    frag0_spec.more_fragments = true;
    frag0_spec.fragment_offset = 0;

    ::tc8::stimulus::Ipv4FrameSpec frag1_spec{};
    frag1_spec.dst_mac        = dst_mac;
    frag1_spec.src_ip         = params.src_ip_frag1.value_or(tester_ip);
    frag1_spec.dst_ip         = dut_ip;
    frag1_spec.ip_id          = params.ip_id_frag1;
    frag1_spec.ip_protocol    = params.ip_protocol_frag1;
    frag1_spec.ttl            = params.ttl_frag1;
    frag1_spec.more_fragments = false;
    frag1_spec.fragment_offset = 1;  // 8 octets / 8 = 1

    ::tc8::stimulus::IpBootTiming t0{};
    t0.initial_wait   = initial_wait;
    t0.post_send_wait = inter_frag_wait;
    const int rc0 = ::tc8::stimulus::emitIpv4Frame(iface, frag0_spec, frag0_payload, t0);
    if (rc0 != 0) return rc0;

    ::tc8::stimulus::IpBootTiming t1{};
    t1.initial_wait   = std::chrono::milliseconds{0};
    t1.post_send_wait = post_send_wait;
    return ::tc8::stimulus::emitIpv4Frame(iface, frag1_spec, frag1_payload, t1);
}

// Builds and emits ONLY the second fragment of the reassembled Echo
// Request — used by FRAGMENTS_02/03/04 phase 2's retry. The DUT's
// reassembly buffer still holds frag 0 from phase 1 (matching tuple,
// offset=0, MF=1); this frag 1 carries the canonical matched tuple
// (tester src, kFragmentsIpId1, ICMP protocol) and completes the
// bucket → DUT reassembles → Echo Reply. No override knobs — all
// three compound cases retry with the same matched tuple.
inline int emitFragmentOne(std::string_view iface,
                           const ::tc8::TestConfig& cfg,
                           const std::array<std::uint8_t, 6>& dst_mac) {
    const auto body = ::tc8::stimulus::buildIcmpEchoRequestBody(
        ::tc8::stimulus::kIcmpEchoId,
        ::tc8::stimulus::kIcmpEchoSeq,
        kFragmentsEchoPayload.data(),
        static_cast<std::uint32_t>(kFragmentsEchoPayload.size()));

    std::vector<std::uint8_t> frag1_payload(body.begin() + 8, body.end());

    ::tc8::stimulus::Ipv4FrameSpec frag1_spec{};
    frag1_spec.dst_mac        = dst_mac;
    frag1_spec.src_ip         = cfg.icmpv4.tester_ip;
    frag1_spec.dst_ip         = cfg.icmpv4.dut_iface_ip;
    frag1_spec.ip_id          = kFragmentsIpId1;
    frag1_spec.ip_protocol    = kFragmentsProtocolIcmp;
    frag1_spec.more_fragments = false;
    frag1_spec.fragment_offset = 1;

    return ::tc8::stimulus::emitIpv4Frame(iface, frag1_spec, frag1_payload);
}

// Schedule phase-2 frag 1 emission via the runner's
// `IStimulusScheduler` so the action fires from `tick()` on the poll-
// loop thread the moment SCXML lands on `listening_phase2`. The
// compound template can then distinguish a DUT that wrongly
// reassembled phase 1's mismatched tuple from one that correctly
// reassembled phase 2's matched tuple.
//
// Driven by state entry, not wall time, so the trait is decoupled
// from `listening_phase1`'s `<send delay="2s"/>`: if the SCXML
// deadline ever changes, the trait does not have to track it. The
// action fires on the first `tick()` after the
// `listening_phase1 → listening_phase2` transition lands, so phase 2
// frag 1 hits the wire while `listening_phase2`'s 3 s deadline window
// is fully ahead of it. Linux `net.ipv4.ipfrag_time` (default 30 s)
// keeps frag 0's bucket alive across the inter-state latency.
//
// Replaces the prior detached-`std::thread` workaround AND the
// schedule(delay, …) wall-time variant. Cleaner because: (a) verdict-
// reach short-circuits the queue — a phase-1 fail leaves phase 2
// unfired without any thread to leak; (b) action runs on the same
// thread as pcap drain / SCXML step, so there is no concurrent
// emit/capture interleaving; (c) no SIGKILL race on early process
// exit; (d) no SCXML/trait timing duplication. See
// `IStimulusScheduler` in `test_runner.h` for the full rationale.
inline void schedulePhase2FragmentOneOnStateEntry(
    IStimulusScheduler &scheduler,
    int target_state_id,
    std::string_view iface,
    const ::tc8::TestConfig &cfg,
    std::array<std::uint8_t, 6> dst_mac) {
    std::string iface_copy(iface);
    ::tc8::TestConfig cfg_copy = cfg;
    scheduler.scheduleAfterStateEntry(target_state_id,
        [iface_copy, cfg_copy, dst_mac]() {
            emitFragmentOne(iface_copy, cfg_copy, dst_mac);
        });
}

// Dispatch helper — identical shape to `icmpv4::dispatchIcmpFrame`
// with an explicit Echo Reply (type=0) narrowing. Re-exported here
// so FRAGMENTS traits can include just this header without also
// pulling in `icmpv4_pilot_common.h`'s stimulus overrides they
// don't use.
template <typename SM>
inline void dispatchEchoReply(typename SM::CapturedType& c, SM& sm,
                              const ::tc8::CapturedEvent& ev) {
    const auto* f = std::get_if<::tc8::Icmpv4Frame>(&ev);
    if (f == nullptr) return;
    if (f->type != 0) return;  // Echo Reply only
    ::tc8::fillIcmpv4CapturedFromFrame(c, *f);
    sm.raiseExternal(SM::PolicyType::Event::Icmp_observed);
    sm.step();
}

}  // namespace tc8::sce::ipv4::fragments
