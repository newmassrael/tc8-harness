#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_message_16_sm.h"

namespace tc8::sce::cases {

using SdMessage16SM =
    ::SCE::Generated::someipsrv_sd_message_16::someipsrv_sd_message_16;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.16 — Subscribe with UNKNOWN-SERVICE-ID (0xFFFE)
// drives a Nack with TTL=0 that echoes Service ID = 0xFFFE
// (TR_SOMEIP §6.7.4.2.4).
template <>
struct TestCaseTraits<cases::SdMessage16SM>
    : SomeIpSdOnlyBase<cases::SdMessage16SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_16";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroupNack shall echo Service ID for unknown ServiceID";

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

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage16SM, someipsrv_sd_message_16)
