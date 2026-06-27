#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_021_sm.h"

namespace tc8::sce::cases {

using SomeipEts021SM = ::SCE::Generated::someip_ets_021::someip_ets_021;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_021 — echoINT8 round-trip over UDP.
// Stimulus payload byte 0xD6 = -42 (Int8 two's complement) verifies
// sign preservation across CommonAPI's Int8 ↔ uint8_t wire round-trip.
template <>
struct TestCaseTraits<cases::SomeipEts021SM> : SomeIpAnyBase<cases::SomeipEts021SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_021";
    static constexpr std::string_view kDescription =
        "echoINT8 round-trip — DUT echoes the Int8 value sent in Method Request";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x000E;
        target.payload = {0xD6};  // -42 as Int8 two's complement.
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts021SM, someip_ets_021)
