#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_sd_message_03_sm.h"

namespace tc8::sce::cases {

using SdMessage03SM =
    ::SCE::Generated::someipsrv_sd_message_03::someipsrv_sd_message_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.3 — OfferService entry shall carry the configured
// Major Version (TR_SOMEIP_00351). Verified against expected.major_version
// populated from --expect major_version=<n>.
template <>
struct TestCaseTraits<cases::SdMessage03SM>
    : SomeIpSdOnlyBase<cases::SdMessage03SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_03";
    static constexpr std::string_view kSpecSection = "5.1.5.3.3";
    static constexpr std::string_view kDescription =
        "OfferService entry Major Version shall carry SdServerServiceMajorVersion";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage03SM, someipsrv_sd_message_03)
