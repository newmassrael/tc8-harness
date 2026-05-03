#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_message_14_sm.h"

namespace tc8::sce::cases {

using SdMessage14SM =
    ::SCE::Generated::someipsrv_sd_message_14::someipsrv_sd_message_14;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.14 — Subscribe with UNKNOWN-SERVICE-ID (0xFFFE)
// drives a Nack with TTL=0 (TR_SOMEIP §6.7.4.2.4).
template <>
struct TestCaseTraits<cases::SdMessage14SM>
    : SomeIpSdOnlyBase<cases::SdMessage14SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_14";
    static constexpr std::string_view kSpecSection = "5.1.5.3.14";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroupNack TTL shall be 0 (unknown ServiceID)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::SubscribeEventgroupTarget target{};
        target.service_id = ::tc8::sd_test_unknown::kServiceId;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, target,
            cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:           return "pass";
            case State::Fail_ttl:       return "fail:nack_entry_ttl_not_zero";
            case State::Fail_timeout:   return "fail:no_qualifying_sd_message_within_listen_window";
            default:                    return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage14SM, someipsrv_sd_message_14)
