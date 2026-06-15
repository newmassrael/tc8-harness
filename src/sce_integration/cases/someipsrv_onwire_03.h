#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_onwire_03_sm.h"

namespace tc8::sce::cases {

using Onwire03SM = ::SCE::Generated::someipsrv_onwire_03::someipsrv_onwire_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.6.3 — Server copies Request ID (Client ID + Session ID)
// from the Request to the Response. Tester sends sentinel client_id =
// 0xCAFE, session_id = 0x1234; pass requires the Response echoes both
// halves verbatim.
template <>
struct TestCaseTraits<cases::Onwire03SM> : SomeIpAnyBase<cases::Onwire03SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_ONWIRE_03";
    static constexpr std::string_view kSpecSection = "5.1.5.6.3";
    static constexpr std::string_view kDescription =
        "Method Response copies the Request ID (Client ID + Session ID) from the Request";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.client_id = 0xCAFE;
        target.session_id = 0x1234;
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Onwire03SM, someipsrv_onwire_03)
