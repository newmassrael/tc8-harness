#pragma once

#include <string>
#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"
#include "tc8/rfc3927_constants.h"

#include "sce_integration/arp_captured.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_14_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection14SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_14::ipv4_autoconf_address_selection_14;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection14SM> {
    using SM    = cases::Ipv4AutoconfAddressSelection14SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_14";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "DUT rate-limits Probe emissions to one new address per "
        "RATE_LIMIT_INTERVAL after MAX_CONFLICTS=10 conflicts "
        "(RFC 3927 §2.2.1, MUST)";
    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Arp;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Stimulus: kick the LL state machine with the fast-conflict
    // envelope (rate_limit_interval = 3 s). Dispatch reads `iface`
    // from the 4-arg overload directly — no Captured-side stash —
    // so the runtime context stays out of the wire-derived snapshot.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFastConflict(
            cfg, iface, cfg.dut.mac);
    }

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

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection14SM,
                  ipv4_autoconf_address_selection_14)
