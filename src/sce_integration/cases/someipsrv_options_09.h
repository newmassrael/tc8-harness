#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_options_09_sm.h"

namespace tc8::sce::cases {

using Options09SM =
    ::SCE::Generated::someipsrv_options_09::someipsrv_options_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Options09SM>
    : SomeIpSdOnlyBase<cases::Options09SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_OPTIONS_09";
    static constexpr std::string_view kSpecSection = "5.1.5.5.9";
    static constexpr std::string_view kDescription =
        "Type field of the IPv4 Multicast Option shall be 0x14";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0008;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe, cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:         return "pass";
            case State::Fail_type:    return "fail:no_ipv4_multicast_option_with_type_0x14";
            case State::Fail_timeout: return "fail:no_qualifying_sd_message_within_listen_window";
            default:                  return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Options09SM, someipsrv_options_09)
