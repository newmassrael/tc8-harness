#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_message_15_sm.h"

namespace tc8::sce::cases {

using SdMessage15SM =
    ::SCE::Generated::someipsrv_sd_message_15::someipsrv_sd_message_15;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.15 — Subscribe with UNKNOWN-SERVICE-ID drives
// a Nack that echoes Instance ID, Eventgroup ID, Major Version and
// Reserved fields and sets TTL=0 (TR_SOMEIP §6.7.4.2.4).
template <>
struct TestCaseTraits<cases::SdMessage15SM>
    : SomeIpSdOnlyBase<cases::SdMessage15SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_15";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroupNack shall echo Instance/Eventgroup/Major/Reserved fields";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::SubscribeEventgroupTarget target{};
        target.service_id = ::tc8::sd_test_unknown::kServiceId;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, target,
            cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage15SM, someipsrv_sd_message_15)
