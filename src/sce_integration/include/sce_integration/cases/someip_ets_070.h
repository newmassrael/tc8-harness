#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_070_sm.h"

namespace tc8::sce::cases {

using SomeipEts070SM = ::SCE::Generated::someip_ets_070::someip_ets_070;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_070 — DUT must reject (or silently ignore)
// an echoUNION Request whose SOME/IP Length header overshoots the actual
// UDP payload. Stimulus reuses the ETS_038 9-byte Type 2 (uint8 = 0x42)
// baseline and sets `length_override = 0x100` so the SOME/IP header
// claims 256 bytes follow Request ID while UDP only carries 9. vsomeip's
// `udp_server_endpoint_impl` detects the mismatch against the received
// UDP size and drops the frame; both reject and silent-ignore paths
// satisfy PRS_SOMEIP_00119/00126 via the lenient ETS_001/_002 verdict
// pattern.
template <>
struct TestCaseTraits<cases::SomeipEts070SM> : SomeIpAnyBase<cases::SomeipEts070SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_070";
    static constexpr std::string_view kDescription =
        "echoUNION SOME/IP length overshoots UDP payload — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.method_id = 0x0019;
        target.payload = {
            // unionLength_BE = 0x00000001 (sizeof(uint8) = 1 byte)
            0x00, 0x00, 0x00, 0x01,
            // unionType_BE = 0x00000002 (Type 2 = uint8)
            0x00, 0x00, 0x00, 0x02,
            // value = 0x42 (uint8)
            0x42,
        };
        // SOME/IP Length lies: claims 256 bytes follow Request ID while
        // UDP only carries 17 (8 Request-ID-tail + 9 union payload).
        target.length_override = 0x100u;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts070SM, someip_ets_070)
