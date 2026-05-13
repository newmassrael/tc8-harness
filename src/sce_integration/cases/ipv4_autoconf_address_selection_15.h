#pragma once

#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"
#include "tc8/rfc3927_constants.h"

#include "sce_integration/arp_captured.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_15_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection15SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_15::ipv4_autoconf_address_selection_15;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection15SM> {
    using SM    = cases::Ipv4AutoconfAddressSelection15SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_15";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "DUT rate-limit persists across multiple windows: post-silence "
        "Probe targets a fresh LL and a single conflict puts the DUT "
        "back into RATE_LIMIT_INTERVAL silence (RFC 3927 §2.2.1, MUST)";
    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Arp;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Stimulus: same fast-conflict envelope as _14 (rate_limit_interval
    // = 3 s). The dispatcher reads `iface` from the 4-arg overload.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFastConflict(
            cfg, iface, cfg.arp.dut_real_mac);
    }

    // Dispatch reuses _14's helper with the post-silence branch
    // engaged: `wait_repick_state_id` keys the emit-trigger,
    // `post_silence_success_state_id` gates it so a doomed
    // post-silence Probe (LL == previous) leaves the wire silent
    // while the SCXML routes to `fail_post_silence_repeat`.
    static void dispatch(Captured& c, SM& sm,
                         const ::tc8::CapturedEvent& ev,
                         std::string_view iface) {
        ::tc8::sce::linklocal::RepeatedConflictDispatchSpec<SM> spec{
            iface,
            static_cast<int>(State::Cycle),
            Event::Conflicts_complete,
            ::tc8::sce::linklocal::ConflictArpVariant::Request,
            ::tc8::rfc3927::kMaxConflicts,
            static_cast<int>(State::Wait_repick),
            static_cast<int>(State::Silence_watch_2),
        };
        ::tc8::sce::linklocal::dispatchArpFrameWithRepeatedConflictEmit<SM>(
            c, sm, ev, spec);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_initial_probe:
                return "fail:no_arp_probe_after_ll_start";
            case State::Fail_conflicts_incomplete:
                return "fail:dut_did_not_re_probe_through_max_conflicts";
            case State::Fail_cycle_repeat:
                return "fail:dut_re_probed_with_stale_link_local_address";
            case State::Fail_emitted_during_silence_1:
                return "fail:dut_emitted_arp_during_first_rate_limit_silence";
            case State::Fail_no_post_silence_probe:
                return "fail:dut_did_not_emit_arp_after_rate_limit_recovery";
            case State::Fail_post_silence_repeat:
                return "fail:dut_post_silence_probe_targets_previous_ll";
            case State::Fail_emitted_during_silence_2:
                return "fail:dut_emitted_arp_during_second_rate_limit_silence";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection15SM,
                  ipv4_autoconf_address_selection_15)
