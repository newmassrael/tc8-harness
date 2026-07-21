#pragma once

#include <chrono>
#include <string_view>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_061_sm.h"

namespace tc8::sce::cases {

using SomeipEts061SM = ::SCE::Generated::someip_ets_061::someip_ets_061;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_061 — Sending_two_SOMEIP_Messages_in_a_row.
// Tester packs two SOME/IP Method Requests (echoUINT8 / Method 0x0008
// + echoENUM / Method 0x0017) into a single UDP datagram via
// `emitBundledMethodRequestsUdp`. Per PRS_SOMEIP_00142 / 00569 the
// DUT must walk the bundle by per-message Length header and emit a
// Method Response for each Request. Spec p589 Pass Criteria: "DUT
// returns the method results of both requests in one message or
// separate messages" — Linux DUT (CommonAPI-on-vsomeip) emits two
// distinct UDP datagrams, one per Response, so the SCXML pins each
// reply on its own session_id (0x0001 / 0x0002) in successive
// phases. Direct lift of the ETS_069 3-bundle pattern with 2
// messages and method-id varying (echoUINT8 + echoENUM) instead of
// the same array method.
template <>
struct TestCaseTraits<cases::SomeipEts061SM> : SomeIpAnyBase<cases::SomeipEts061SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_061";
    static constexpr std::string_view kDescription =
        "Two SOME/IP Method Requests in one UDP datagram — DUT replies to both";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::vector<::tc8::stimulus::SomeIpRpcMessage> bundle;
        bundle.reserve(2);

        ::tc8::stimulus::SomeIpRpcMessage m1{};
        m1.method_id  = 0x0008;            // echoUINT8 (METHOD-ID-1-SI-1).
        m1.session_id = 0x0001;
        m1.payload    = {0x42};            // 1-byte UInt8.
        bundle.push_back(m1);

        ::tc8::stimulus::SomeIpRpcMessage m2{};
        m2.method_id  = 0x0017;            // echoENUM (per spec p401-420 table).
        m2.session_id = 0x0002;
        m2.payload    = {0x01};            // 1-byte EtsEnum (VALUE_B = 1).
        bundle.push_back(m2);

        ::tc8::stimulus::emitBundledMethodRequestsUdp(iface, bundle,
                                                     std::chrono::milliseconds(500),
                                                     ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts061SM, someip_ets_061)
