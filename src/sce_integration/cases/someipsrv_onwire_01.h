#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_onwire_01_sm.h"

namespace tc8::sce::cases {

using Onwire01SM = ::SCE::Generated::someipsrv_onwire_01::someipsrv_onwire_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.6.1 — Response/Error transport endpoints match the
// Request. Tester invokes echoUINT8; pass requires the Response's
// src_ip == expected.dut_iface_ip AND src_port == expected.udp_port.
// The dst half (tester IP + ephemeral source port) is kernel-routing
// responsibility; asserting only the DUT-controlled src half keeps
// the test deterministic without a fixed tester-port binding.
template <>
struct TestCaseTraits<cases::Onwire01SM> : SomeIpAnyBase<cases::Onwire01SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_ONWIRE_01";
    static constexpr std::string_view kDescription =
        "Method Response transport src endpoint matches DUT SERVICE-ID-1 UDP endpoint";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Onwire01SM, someipsrv_onwire_01)
