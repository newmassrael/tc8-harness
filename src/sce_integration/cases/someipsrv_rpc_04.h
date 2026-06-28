#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_04_sm.h"

namespace tc8::sce::cases {

using Rpc04SM = ::SCE::Generated::someipsrv_rpc_04::someipsrv_rpc_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.4 — Fire&Forget Requests have no Response. Tester
// sends SOMEIP_MSG_TYPE_REQUEST_NO_RETURN (0x01) to the regular echo
// method (METHOD-ID-1-SI-1 = 0x08) so vsomeip sees a F&F invocation
// of a request/response method; per spec the DUT must skip sending a
// Response.
template <>
struct TestCaseTraits<cases::Rpc04SM> : SomeIpAnyBase<cases::Rpc04SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_04";
    static constexpr std::string_view kDescription =
        "Fire&Forget Request elicits no Response";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;     // REQUEST_NO_RETURN
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc04SM, someipsrv_rpc_04)
