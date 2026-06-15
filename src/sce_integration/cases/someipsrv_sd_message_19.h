#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_message_19_sm.h"

namespace tc8::sce::cases {

using SdMessage19SM =
    ::SCE::Generated::someipsrv_sd_message_19::someipsrv_sd_message_19;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.19 — Subscribe with UNKNOWN-EVENT-GROUP-ID
// (0xFFFE) drives a Nack echoing Eventgroup ID = 0xFFFE with TTL=0
// (TR_SOMEIP §6.7.4.2.4).
template <>
struct TestCaseTraits<cases::SdMessage19SM>
    : SomeIpSdOnlyBase<cases::SdMessage19SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_19";
    static constexpr std::string_view kSpecSection = "5.1.5.3.19";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroupNack shall echo Eventgroup ID for unknown EventGroupID";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::SubscribeEventgroupTarget target{};
        target.eventgroup_id = ::tc8::sd_test_unknown::kEventGroupId;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, target,
            cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage19SM, someipsrv_sd_message_19)
