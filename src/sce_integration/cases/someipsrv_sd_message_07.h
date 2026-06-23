#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_sd_message_07_sm.h"

namespace tc8::sce::cases {

using SdMessage07SM =
    ::SCE::Generated::someipsrv_sd_message_07::someipsrv_sd_message_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.7 — OfferService entry TTL shall carry the
// configured service-instance lifetime (TR_SOMEIP_00356). The spec
// body's lifetime-expiry sub-test (wait TTL seconds, send a method
// request, expect no response) lives on a separate observation
// surface (event/method flow) and is deferred — this case verifies
// only the TTL field invariant. SERVICE-ID-1-TTL injected via
// --expect ttl=<n>.
template <>
struct TestCaseTraits<cases::SdMessage07SM>
    : SomeIpSdOnlyBase<cases::SdMessage07SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_07";
    static constexpr std::string_view kDescription =
        "OfferService entry TTL shall carry SERVICE-ID-1-TTL";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage07SM, someipsrv_sd_message_07)
