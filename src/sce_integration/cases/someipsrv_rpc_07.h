#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_07_sm.h"

namespace tc8::sce::cases {

using Rpc07SM = ::SCE::Generated::someipsrv_rpc_07::someipsrv_rpc_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.7 — The receiver of a return_code shall ignore the
// values of the two most significant bits. Tester sends a Method
// Request to METHOD-ID-1-SI-1 (echoUINT8 = 0x08) with return_code =
// 0xC0; DUT must process the request normally and reply with a
// Response carrying return_code = E_OK.
template <>
struct TestCaseTraits<cases::Rpc07SM> : SomeIpAnyBase<cases::Rpc07SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_07";
    static constexpr std::string_view kSpecSection = "5.1.5.7.7";
    static constexpr std::string_view kDescription =
        "Receiver ignores top 2 bits of Request return_code";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.return_code = 0xC0;
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc07SM, someipsrv_rpc_07)
