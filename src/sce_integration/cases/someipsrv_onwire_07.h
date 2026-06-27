#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_onwire_07_sm.h"

namespace tc8::sce::cases {

using Onwire07SM = ::SCE::Generated::someipsrv_onwire_07::someipsrv_onwire_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.6.7 — Message Type and Response after a Request.
// Tester sends Method Request (msg_type=0x00) to METHOD-ID-1-SI-1
// (echoUINT8 0x0008); pass requires the matched Response carries
// message_type=0x80 AND return_code=E_OK (0x00).
template <>
struct TestCaseTraits<cases::Onwire07SM> : SomeIpAnyBase<cases::Onwire07SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_ONWIRE_07";
    static constexpr std::string_view kDescription =
        "Method Response carries message_type=0x80 and return_code=E_OK after a Request";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Onwire07SM, someipsrv_onwire_07)
