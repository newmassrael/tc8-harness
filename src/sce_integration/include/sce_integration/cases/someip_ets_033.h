#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_033_sm.h"

namespace tc8::sce::cases {

using SomeipEts033SM = ::SCE::Generated::someip_ets_033::someip_ets_033;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_033 — echoUINT8ArrayMinSize_too_short.
// Spec target is MALFORMED_MESSAGE on a too-short array, but
// CommonAPI-SOMEIP on Linux ignores SomeIpArrayMinLength when the
// length-width is non-zero (deployment-spec semantics). We exercise
// the malformed-length axis on the same METHOD-ID 0x0037 instead —
// length_override claims 0x100 bytes follow Request ID while the UDP
// datagram carries a 2-element array body, so vsomeip rejects per
// PRS_SOMEIP_00099. Pass cond mirrors ETS_001/_002 (Error Response
// OR silent ignore).
template <>
struct TestCaseTraits<cases::SomeipEts033SM> : SomeIpAnyBase<cases::SomeipEts033SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_033";
    static constexpr std::string_view kDescription =
        "echoUINT8ArrayMinSize too-short — DUT must reject malformed length";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.method_id = 0x0037;
        // 32-bit BE length prefix = 2 + 2 array bytes — array shorter
        // than the spec-defined minimum (3). Length_override drives a
        // SOME/IP-header / UDP-datagram size mismatch on top so vsomeip
        // rejects the frame at parse time (the path Linux DUTs actually
        // observe; CommonAPI's MinSize axis is unenforced on this stack).
        target.payload = {0x00, 0x00, 0x00, 0x02, 0x10, 0x11};
        target.length_override = 0x100u;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts033SM, someip_ets_033)
