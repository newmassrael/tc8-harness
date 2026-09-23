#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_fragments_common.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_11_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly11SM = ::SCE::Generated::ipv4_reassembly_11::ipv4_reassembly_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Reassembly11SM>
    : Ipv4FragmentEchoBase<cases::Ipv4Reassembly11SM> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_11";
    static constexpr std::string_view kDescription =
        "DUT reassembles a 2-fragment Echo Request whose first "
        "fragment carries Large TTL (timer extended) — frag 1 "
        "arrives after ipIniReassembleTimeout + tolerance, DUT "
        "still emits Echo Reply (RFC 791 §3.2)";

    // Two-fragment Echo Request with kReassemblyLargeTtl (=255) on
    // both halves and a 3 s inter-fragment wait. The orchestrator's
    // dut_ns toggle drops `net.ipv4.ipfrag_time` to 2 s so the spec's
    // "wait > ipIniReassembleTimeout + tolerance" condition is
    // exercised in seconds rather than tens of seconds. Same shape as
    // REASSEMBLY_12 (opposite TTL axis); FragmentPair helper builds
    // the 16 B ICMP body once and slices 8/8.
    //
    // Frag 0 is sent here and frag 1 is SCHEDULED, so the SCXML listens
    // across the wait. A DUT whose timer ignores TTL expires the bucket
    // inside the wait and reports it with a Time Exceeded code 1 that
    // quotes frag 0; that report is the observed violation. Scheduling
    // frag 1 is NOT what makes the report visible: a frame captured
    // during a blocking stimulus waits in the capture ring and is
    // dispatched once the listen window opens (measured 2026-09-24:
    // REASSEMBLY_10's phase-B report, sent inside its blocking wait,
    // reached the SCXML). The SCXML's 6 s deadline must stay above
    // kInterFragmentWait.
    //
    // Linux (verified 2026-09-23, kernel 7.0): ip_frag_queue arms the
    // bucket timer from ip4_frags.timeout regardless of arriving TTL —
    // no RFC 791 §3.2 MAX(TLB, TTL) extension — and sends the Time
    // Exceeded 2 s after frag 0 (see docs/tech-debt.md TD-28). A DUT that follows
    // RFC 791 §3.2 verbatim passes on the same wire shape.
    static constexpr std::chrono::milliseconds kInterFragmentWait{3000};

    // The early-expiry report above is this case's fail_timer_not_extended.
    static constexpr ipv4::fragments::ReassemblyExpiryRole kReassemblyExpiry =
        ipv4::fragments::ReassemblyExpiryRole::kGraded;

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        const auto pair = ::tc8::sce::ipv4::reassembly::buildReassembly11FragmentPair(cfg);

        ::tc8::stimulus::IpBootTiming t0{};
        t0.initial_wait = std::chrono::milliseconds{200};
        ::tc8::stimulus::emitIpv4Frame(iface, pair.frag0_spec, pair.frag0_payload, t0);

        std::string iface_copy(iface);
        scheduler.schedule(kInterFragmentWait, [iface_copy, pair]() {
            ::tc8::stimulus::IpBootTiming t1{};
            t1.initial_wait = std::chrono::milliseconds{0};
            ::tc8::stimulus::emitIpv4Frame(iface_copy, pair.frag1_spec, pair.frag1_payload, t1);
        });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly11SM, ipv4_reassembly_11)
