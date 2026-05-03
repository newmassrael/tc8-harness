#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_sd_message_04_sm.h"

namespace tc8::sce::cases {

using SdMessage04SM =
    ::SCE::Generated::someipsrv_sd_message_04::someipsrv_sd_message_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.4 — Same Major Version invariant as SD_MESSAGE_03;
// the {any vs. specific} axis lives on the Find side and the Offer
// always carries the configured value.
template <>
struct TestCaseTraits<cases::SdMessage04SM>
    : SomeIpSdOnlyBase<cases::SdMessage04SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_04";
    static constexpr std::string_view kSpecSection = "5.1.5.3.4";
    static constexpr std::string_view kDescription =
        "OfferService entry Major Version shall carry SdServerServiceMajorVersion";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_major_version:  return "fail:offer_entry_major_version_mismatch";
            case State::Fail_timeout:        return "fail:no_qualifying_sd_message_within_listen_window";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage04SM, someipsrv_sd_message_04)
