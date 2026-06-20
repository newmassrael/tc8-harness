#pragma once

#include <string>
#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"
#include "tc8/rfc3927_constants.h"
#include "tc8/upper_tester_protocol.h"

#include "sce_integration/arp_captured.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_15_neg2_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection15Neg2SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_15_neg2::ipv4_autoconf_address_selection_15_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection15Neg2SM> {
    using SM    = cases::Ipv4AutoconfAddressSelection15Neg2SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_15_NEG2";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "Self-validation of ADDRESS_SELECTION_15 guard 2: tc8-dut "
        "SkipFirstRateLimitSilence fault-injection emits a Probe during "
        "the first rate-limit silence window (RFC 3927 §2.2.1)";
    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Arp;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggyConflict(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kFlavorSkipFirstRateLimitSilence);
    }

    // Violation lands in the first silence window, so the dispatch omits
    // the post-silence branch.
    static void dispatch(Captured& c, SM& sm,
                         const ::tc8::CapturedEvent& ev,
                         std::string_view iface) {
        ::tc8::sce::linklocal::RepeatedConflictDispatchSpec<SM> spec{
            iface,
            static_cast<int>(State::Cycle),
            Event::Conflicts_complete,
            ::tc8::sce::linklocal::ConflictArpVariant::Request,
            ::tc8::rfc3927::kMaxConflicts,
        };
        ::tc8::sce::linklocal::dispatchArpFrameWithRepeatedConflictEmit<SM>(
            c, sm, ev, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection15Neg2SM,
                  ipv4_autoconf_address_selection_15_neg2)
