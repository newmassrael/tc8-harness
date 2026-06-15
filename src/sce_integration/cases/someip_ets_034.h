#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_034_sm.h"

namespace tc8::sce::cases {

using SomeipEts034SM = ::SCE::Generated::someip_ets_034::someip_ets_034;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_034 — echoUINT8E2E. The spec models AUTOSAR
// E2E protection as a 5-arg payload (4×UInt32 BE + 1×UInt8) carrying the
// E2E header fields (len, counter, dataID, crc) plus a Uint8 value.
// Spec p401-420 echoUINT8E2E row equates Req↔Res field-by-field
// ("echoUINT8E2E_ReqArg1 = echoUINT8E2E_ResArg1, etc.") rather than
// mandating CRC recomputation on the DUT, so the DUT-side override is a
// plain echo and no E2E plugin is required (PRS_SOMEIP_00065 is about
// the framing, not the algorithm).
//
// Wire shape (17 bytes back-to-back, CommonAPI default):
//   [len_BE 0x00000005][counter_BE 0x00000001]
//   [dataID_BE 0xCAFEBABE][crc_BE 0xDEADBEEF][value 0x42]
template <>
struct TestCaseTraits<cases::SomeipEts034SM> : SomeIpAnyBase<cases::SomeipEts034SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_034";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUINT8E2E — DUT echoes the 4×UInt32 E2E header + UInt8 value unchanged";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x000B;
        target.payload = {
            // len = 0x00000005 (BE)
            0x00, 0x00, 0x00, 0x05,
            // counter = 0x00000001 (BE)
            0x00, 0x00, 0x00, 0x01,
            // dataID = 0xCAFEBABE (BE)
            0xCA, 0xFE, 0xBA, 0xBE,
            // crc = 0xDEADBEEF (BE)
            0xDE, 0xAD, 0xBE, 0xEF,
            // value = 0x42
            0x42,
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts034SM, someip_ets_034)
