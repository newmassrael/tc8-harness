#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_103_sm.h"

namespace tc8::sce::cases {

using SomeipEts103SM = ::SCE::Generated::someip_ets_103::someip_ets_103;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_103 — SD_ClientServiceGetLastValueOfEventTCP.
// Stimulus chain:
//   1. emitFindServiceBoot — SERVICE-ID-1 server warm-up.
//   2. clientServiceActivate (Method 0x2F).
//   3. clientServiceSubscribeEventgroup (Method 0x32) — DUT-side proxy
//      subscribes to ets3 TargetEventReliable (TCP).
//   4. (spec procedure step 5: tester sends TCP Event UInt8=0x08 — not
//      implemented in this trait; tc8-dut's GetLastValueOfEventTCP cell
//      is pre-initialised to 0x08 so the response wire shape is valid.)
//   5. clientServiceGetLastValueOfEventTCP (Method 0x3B) — observe
//      Response payload 0x08.
// Per PRS_SOMEIPSD_00362 / 00380 the DUT must respond with the cached
// UInt8. Spec-canonical Method ID 0x3B (TC8 §5.1.4 Table 1).
template <>
struct TestCaseTraits<cases::SomeipEts103SM> : SomeIpAnyBase<cases::SomeipEts103SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_103";
    static constexpr std::string_view kDescription =
        "Client-Mode + GetLastValueOfEventTCP — DUT responds with cached UInt8 (TCP)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // 1. clientServiceActivate.
        ::tc8::stimulus::MethodRequestTarget activate{};
        activate.method_id    = 0x002F;
        activate.message_type = 0x01;  // Fire&Forget
        activate.payload      = {0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, activate, {}, ::tc8::sce::someipUdpMethodDest(cfg));
        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        // 2. clientServiceSubscribeEventgroup.
        ::tc8::stimulus::MethodRequestTarget subscribe{};
        subscribe.method_id    = 0x0032;
        subscribe.message_type = 0x01;
        subscribe.payload      = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, subscribe, {}, ::tc8::sce::someipUdpMethodDest(cfg));
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));

        // 3. clientServiceGetLastValueOfEventTCP — Method 0x3B Request /
        // Response (no payload on Request; Response carries UInt8).
        ::tc8::stimulus::MethodRequestTarget get_last{};
        get_last.method_id = 0x003B;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get_last, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts103SM, someip_ets_103)
