#pragma once

#include <chrono>
#include <memory>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/subscribe_tcp_session.h"

#include "someip_ets_155_sm.h"

namespace tc8::sce::cases {

using SomeipEts155SM = ::SCE::Generated::someip_ets_155::someip_ets_155;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_155 — Subscribe / StopSubscribe / Subscribe
// chain on eg 0x0002. Per PRS_SOMEIPSD_00263 / 00386 the DUT shall Ack
// both Subscribes and silently accept the Stop. Stimulus paces the three
// SD emits ~1 s apart so vsomeip emits two distinct Acks rather than
// bundling them within one cyclic SD response window.
template <>
struct TestCaseTraits<cases::SomeipEts155SM> : SomeIpAnyBase<cases::SomeipEts155SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_155";
    static constexpr std::string_view kDescription =
        "Subscribe → StopSubscribe → Subscribe — DUT Acks both subscribes";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IBackgroundServiceOwner& owner) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // eg 0x0002 is mixed-reliability: hold one TCP connection so vsomeip
        // Acks the dual-option Subscribes; the Sub_1 -> StopSubscribe -> Sub_2
        // sequence is exercised over that held connection.
        auto session = std::make_unique<::tc8::stimulus::SubscribeEventgroupTcpSession>(
            iface, ::tc8::sce::someipTcpMethodDest(cfg));
        ::tc8::stimulus::SubscribeDestination sd_dest{};
        sd_dest.ipv4_be = cfg.someip.dut_iface_ip;

        // First Subscribe (Sub_1).
        ::tc8::stimulus::SubscribeEventgroupParams sub1{};
        sub1.target.eventgroup_id = 0x0002;
        sub1.target.ttl = 3;
        sub1.session_id = 0x0001;
        session->subscribeDualParams(sub1, sd_dest);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // StopSubscribe (ttl == 0 per SD §4.2).
        ::tc8::stimulus::SubscribeEventgroupParams stop{};
        stop.target.eventgroup_id = 0x0002;
        stop.target.ttl = 0;
        stop.session_id = 0x0002;
        session->subscribeDualParams(stop, sd_dest);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // Second Subscribe (Sub_2).
        ::tc8::stimulus::SubscribeEventgroupParams sub2{};
        sub2.target.eventgroup_id = 0x0002;
        sub2.target.ttl = 3;
        sub2.session_id = 0x0003;
        session->subscribeDualParams(sub2, sd_dest);

        owner.adoptService(std::move(session));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts155SM, someip_ets_155)
