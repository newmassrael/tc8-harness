#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_basic_01_sm.h"

namespace tc8::sce::cases {

using Basic01SM = ::SCE::Generated::someipsrv_basic_01::someipsrv_basic_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.5.1 — A service shall be identified using the
// Service-ID. Two pass criteria: DUT emits OfferService for SERVICE-ID-1
// (verifies the service-identifier publication side) and DUT replies to
// a Method Request with a Response carrying the same Service ID and
// E_OK return code (verifies the service-identifier match-and-route
// side).
template <>
struct TestCaseTraits<cases::Basic01SM> : SomeIpAnyBase<cases::Basic01SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_BASIC_01";
    static constexpr std::string_view kDescription =
        "Service identified by Service-ID — DUT emits OfferService and "
        "replies to Method Request with a matching Response";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Phase 1: drive the DUT to emit OfferService via a FindService
        // boot sequence. emitFindServiceBoot blocks for the full
        // (initial_wait + retry envelope), so by the time it returns
        // the DUT is well into its OfferService cycle.
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        // Phase 2: invoke echoUINT8 (METHOD-ID-1-SI-1 = 0x0008 on
        // tc8-dut, declared in dut/ets/ets.fdepl). Single 1-byte payload
        // exercises the smallest possible CommonAPI in/out path; the
        // value 0x42 is purely diagnostic — pass criterion checks the
        // SOME/IP header (message_type, return_code, service_id,
        // method_id), not payload bytes.
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Basic01SM, someipsrv_basic_01)
