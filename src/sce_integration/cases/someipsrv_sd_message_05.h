#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_sd_message_05_sm.h"

namespace tc8::sce::cases {

using SdMessage05SM =
    ::SCE::Generated::someipsrv_sd_message_05::someipsrv_sd_message_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.5 — OfferService entry shall carry the configured
// Minor Version (TR_SOMEIP_00351). Verified against expected.minor_version
// populated from --expect minor_version=<n>.
template <>
struct TestCaseTraits<cases::SdMessage05SM>
    : SomeIpSdOnlyBase<cases::SdMessage05SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_05";
    static constexpr std::string_view kSpecSection = "5.1.5.3.5";
    static constexpr std::string_view kDescription =
        "OfferService entry Minor Version shall carry SdServerServiceMinorVersion";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage05SM, someipsrv_sd_message_05)
