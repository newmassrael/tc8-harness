#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_message_01_sm.h"

namespace tc8::sce::cases {

using SdMessage01SM =
    ::SCE::Generated::someipsrv_sd_message_01::someipsrv_sd_message_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.1 — Number Of Instances = 2 produces an OfferService
// SD message carrying two distinct OfferService entries (TR_SOMEIP_00351).
// Stimulus is the same FindService(any-instance) used by the §5.1.5
// baseline; the discriminator is the multi-instance vsomeip.json
// variant + TC8_DUT_INSTANCE_2 env-var that drives a second
// registerService call in dut_main.cpp.
template <>
struct TestCaseTraits<cases::SdMessage01SM>
    : SomeIpSdOnlyBase<cases::SdMessage01SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_01";
    static constexpr std::string_view kSpecSection = "5.1.5.3.1";
    static constexpr std::string_view kDescription =
        "OfferService carries two entries when DUT configured with two instances";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{});
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage01SM, someipsrv_sd_message_01)
