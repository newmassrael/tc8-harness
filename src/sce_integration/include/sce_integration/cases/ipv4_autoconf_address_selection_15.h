#pragma once

#include <string_view>

#include "tc8/captured_event.h"
#include "tc8/rfc3927_constants.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_15_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection15SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_15::ipv4_autoconf_address_selection_15;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection15SM>
    : LinklocalRepeatedConflictBase<cases::Ipv4AutoconfAddressSelection15SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_15";
    static constexpr std::string_view kDescription =
        "DUT rate-limit persists across multiple windows: post-silence "
        "Probe targets a fresh LL and a single conflict puts the DUT "
        "back into RATE_LIMIT_INTERVAL silence (RFC 3927 §2.2.1, MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFastConflict(
            cfg, iface, cfg.dut.mac);
    }

    // Override the base's cycle-only dispatch with the post-silence
    // branch engaged: `Wait_repick` keys the second-window conflict emit,
    // `Silence_watch_2` gates it so a stale post-silence Probe leaves the
    // wire silent while the SCXML routes to fail_post_silence_repeat.
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
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection15SM,
                  ipv4_autoconf_address_selection_15)
