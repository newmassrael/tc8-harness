#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_12_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection12SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_12::ipv4_autoconf_address_selection_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection12SM>
    : LinklocalProbeSnapshotBase<cases::Ipv4AutoconfAddressSelection12SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_12";
    static constexpr std::string_view kDescription =
        "DUT re-picks LL address after probing-window ARP Reply "
        "conflict (RFC 3927 §2.2.1, MUST)";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& /*cfg*/,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(ctx.dut);
        ::tc8::sce::linklocal::scheduleConflictArpOnStateEntry(
            ctx.scheduler, static_cast<int>(State::Await_repick),
            ctx.iface, ::tc8::sce::linklocal::ConflictArpVariant::Reply, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection12SM,
                  ipv4_autoconf_address_selection_12)
