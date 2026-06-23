#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_sd_message_08_sm.h"

namespace tc8::sce::cases {

using SdMessage08SM =
    ::SCE::Generated::someipsrv_sd_message_08::someipsrv_sd_message_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.8 — OfferService shall reference at least one
// IPv4 Endpoint Option (TR_SOMEIP_00357). Verified against
// captured.sd_ipv4_endpoint_count populated by parseSdOptionsInto.
template <>
struct TestCaseTraits<cases::SdMessage08SM>
    : SomeIpSdOnlyBase<cases::SdMessage08SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_08";
    static constexpr std::string_view kDescription =
        "OfferService shall carry at least one IPv4 Endpoint Option";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage08SM, someipsrv_sd_message_08)
