#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_sd_message_06_sm.h"

namespace tc8::sce::cases {

using SdMessage06SM =
    ::SCE::Generated::someipsrv_sd_message_06::someipsrv_sd_message_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.6 — Same Minor Version invariant as SD_MESSAGE_05;
// the {any vs. specific} axis lives on the Find side and the Offer
// always carries the configured value.
template <>
struct TestCaseTraits<cases::SdMessage06SM>
    : SomeIpSdOnlyBase<cases::SdMessage06SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_06";
    static constexpr std::string_view kDescription =
        "OfferService entry Minor Version shall carry SdServerServiceMinorVersion";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage06SM, someipsrv_sd_message_06)
