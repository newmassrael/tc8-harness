#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_onwire_04_sm.h"

namespace tc8::sce::cases {

using Onwire04SM = ::SCE::Generated::someipsrv_onwire_04::someipsrv_onwire_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.6.4 — Request IDs may be reused once the Response
// arrived. Tester emits two Method Requests carrying the SAME Request
// ID (client_id 0xCAFE, session_id 0x1234) and expects DUT to reply
// to BOTH. The fail signal is "DUT silently dropped the second
// Request as a stale duplicate".
template <>
struct TestCaseTraits<cases::Onwire04SM> : SomeIpAnyBase<cases::Onwire04SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_ONWIRE_04";
    static constexpr std::string_view kDescription =
        "Request ID may be reused after Response arrived — DUT replies to both Requests";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.client_id = 0xCAFE;
        target.session_id = 0x1234;
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));

        // Second Request reuses the same Request ID. 800 ms gap lets the
        // first Response arrive and gives the SCXML phase 2 transition
        // time to consume it before phase 3 starts watching. The default
        // 500 ms pre_emit_wait would still satisfy phase 2's 5 s window
        // but a clear gap makes the inter-Request ordering deterministic
        // under varying tester load.
        ::tc8::stimulus::MethodRequestTiming retx_timing{};
        retx_timing.pre_emit_wait = std::chrono::milliseconds(800);
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, retx_timing, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Onwire04SM, someipsrv_onwire_04)
