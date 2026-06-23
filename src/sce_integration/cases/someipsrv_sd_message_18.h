#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_message_18_sm.h"

namespace tc8::sce::cases {

using SdMessage18SM =
    ::SCE::Generated::someipsrv_sd_message_18::someipsrv_sd_message_18;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.18 — Subscribe with SERVICE-ID-1-MAJ-VER+1 (2)
// drives a Nack echoing Major Version = 2 with TTL=0
// (TR_SOMEIP §6.7.4.2.4).
template <>
struct TestCaseTraits<cases::SdMessage18SM>
    : SomeIpSdOnlyBase<cases::SdMessage18SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_18";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroupNack shall echo Major Version for unknown MajorVersion";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::SubscribeEventgroupTarget target{};
        // UNKNOWN-MAJOR-VERSION = SERVICE-ID-1-MAJ-VER + 1; the SCXML
        // cond mirrors this with `expected.major_version + 1` so both
        // sides follow whatever identity the operator passes.
        target.major_version = static_cast<std::uint8_t>(cfg.someip.major_version + 1);
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, target,
            cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage18SM, someipsrv_sd_message_18)
