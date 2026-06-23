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
    // both halves and a 3 s inter-fragment wait. The smoke-test.sh
    // dut_ns toggle drops `net.ipv4.ipfrag_time` to 2 s so the spec's
    // "wait > ipIniReassembleTimeout + tolerance" condition is
    // exercised in seconds rather than tens of seconds. Same shape as
    // REASSEMBLY_12 (opposite TTL axis); FragmentPair helper builds
    // the 16 B ICMP body once and slices 8/8.
    //
    // Linux known-fail (verified 2026-04-27, kernel 6.5): Linux's
    // ip_frag_queue calls mod_timer(qp->q.timer, jiffies +
    // ip4_frags.timeout) regardless of arriving TTL — there is no
    // RFC 791 §3.2 MAX(TLB, TTL) extension. With the per-netns
    // ipfrag_time=2 s toggle and the 3 s inter-fragment wait, the
    // bucket expires (inet_frag_kill via ip_expire) before frag 1
    // arrives — orphan frag, no Echo Reply, SCXML 6 s listen window
    // times out → fail:no_echo_reply_after_large_ttl_reassembly.
    //
    // The case stays in tree (excluded from default smoke regression
    // — the smoke harness only runs CLI-positional cases) so a non-
    // Linux DUT (AUTOSAR, vendor IP stack) that follows RFC 791 §3.2
    // verbatim — extending the timer when arriving TTL exceeds the
    // current TLB — passes without re-implementation. See
    // `reference_linux_ip_reassembly_deviations.md`.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::fragments::FragmentPairParams params{};
        params.ip_id_frag0 = ::tc8::sce::ipv4::reassembly::kReassembly11IpId;
        params.ip_id_frag1 = ::tc8::sce::ipv4::reassembly::kReassembly11IpId;
        params.ttl_frag0   = ::tc8::sce::ipv4::reassembly::kReassemblyLargeTtl;
        params.ttl_frag1   = ::tc8::sce::ipv4::reassembly::kReassemblyLargeTtl;

        ::tc8::sce::ipv4::fragments::emitFragmentPair(
            iface, cfg, cfg.arp.dut_iface_mac, params,
            /*initial_wait=*/std::chrono::milliseconds{200},
            /*inter_frag_wait=*/std::chrono::milliseconds{3000},
            /*post_send_wait=*/std::chrono::milliseconds{0});
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly11SM, ipv4_reassembly_11)
