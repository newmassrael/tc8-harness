#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_options_12_sm.h"

namespace tc8::sce::cases {

using Options12SM =
    ::SCE::Generated::someipsrv_options_12::someipsrv_options_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Options12SM>
    : SomeIpSdOnlyBase<cases::Options12SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_OPTIONS_12";
    static constexpr std::string_view kDescription =
        "Second Reserved field of the IPv4 Multicast Option shall be 0x00";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0008;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Options12SM, someipsrv_options_12)
