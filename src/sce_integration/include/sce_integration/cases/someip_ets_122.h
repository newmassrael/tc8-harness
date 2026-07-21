#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_122_sm.h"

namespace tc8::sce::cases {

using SomeipEts122SM = ::SCE::Generated::someip_ets_122::someip_ets_122;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_122 — SD_Interface_Version. Tester sends
// a Method Request for the InterfaceVersion Field Getter (method_id
// 0x25 per spec p401-420 Table 2). tc8-dut does not declare an
// InterfaceVersion attribute, so vsomeip's routing layer emits an
// Error Response (msg_type 0x81 + UNKNOWN_METHOD return_code). Per
// SOME/IP §4.6 / PRS_SOMEIPSD_00357, an Error Response is a method
// response — the spec wording "DUT: returns the method response" is
// satisfied by any msg_type 0x80 OR 0x81 reply. Future DUT firmware
// that declares the field (attribute UInt32 InterfaceVersion in
// ets.fidl + SomeIpGetterID = 0x25 in ets.fdepl) would tighten this
// to msg_type 0x80 only.
template <>
struct TestCaseTraits<cases::SomeipEts122SM> : SomeIpAnyBase<cases::SomeipEts122SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_122";
    static constexpr std::string_view kDescription =
        "InterfaceVersion Field Getter — DUT must respond (any return_code)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.method_id = 0x0025;
        // Field Getter Method Request body is empty per SOME/IP §4.5.
        target.payload = {};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts122SM, someip_ets_122)
