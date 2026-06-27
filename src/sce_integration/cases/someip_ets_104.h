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

#include "someip_ets_104_sm.h"

namespace tc8::sce::cases {

using SomeipEts104SM = ::SCE::Generated::someip_ets_104::someip_ets_104;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_104 — SD_ClientServiceGetLastValueOfEventUDP
// Multicast. Lift of ETS_103 with Method ID 0x3D (UDPMulticast variant).
// Same DUT-side last-value cell pre-init pattern (0x08); tester chain
// emits clientServiceActivate → clientServiceSubscribeEventgroup
// (UDP variant) → clientServiceGetLastValueOfEventUDPMulticast.
template <>
struct TestCaseTraits<cases::SomeipEts104SM> : SomeIpAnyBase<cases::SomeipEts104SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_104";
    static constexpr std::string_view kDescription =
        "Client-Mode + GetLastValueOfEventUDPMulticast — DUT responds with cached UInt8";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::MethodRequestTarget activate{};
        activate.method_id    = 0x002F;
        activate.message_type = 0x01;
        activate.payload      = {0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, activate, {}, ::tc8::sce::someipUdpMethodDest(cfg));
        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        ::tc8::stimulus::MethodRequestTarget subscribe{};
        subscribe.method_id    = 0x0032;
        subscribe.message_type = 0x01;
        subscribe.payload      = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, subscribe, {}, ::tc8::sce::someipUdpMethodDest(cfg));
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));

        ::tc8::stimulus::MethodRequestTarget get_last{};
        get_last.method_id = 0x003D;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get_last, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts104SM, someip_ets_104)
