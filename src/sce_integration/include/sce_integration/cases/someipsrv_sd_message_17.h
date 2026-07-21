#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_message_17_sm.h"

namespace tc8::sce::cases {

using SdMessage17SM =
    ::SCE::Generated::someipsrv_sd_message_17::someipsrv_sd_message_17;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.17 — Subscribe with extractedInstID1+1 (0x0002)
// drives a Nack echoing Instance ID = 0x0002 with TTL=0
// (TR_SOMEIP §6.7.4.2.4).
template <>
struct TestCaseTraits<cases::SdMessage17SM>
    : SomeIpSdOnlyBase<cases::SdMessage17SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_17";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroupNack shall echo Instance ID for unknown InstanceID";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::SubscribeEventgroupTarget target{};
        // UNKNOWN-INSTANCE-ID = extractedInstID1 + 1; the SCXML cond
        // mirrors this with `expected.instance_id + 1` so both sides
        // follow whatever SERVICE-ID-1 identity the operator passes.
        target.instance_id = static_cast<std::uint16_t>(cfg.someip.instance_id + 1);
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, target,
            cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage17SM, someipsrv_sd_message_17)
