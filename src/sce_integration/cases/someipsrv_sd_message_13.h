#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_message_13_sm.h"

namespace tc8::sce::cases {

using SdMessage13SM =
    ::SCE::Generated::someipsrv_sd_message_13::someipsrv_sd_message_13;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.13 — SubscribeEventgroupAck entry shall echo
// Service ID / Instance ID / Major Version / Eventgroup ID / TTL /
// Reserved from the answered Subscribe (TR_SOMEIP_00388). Tester
// emits Subscribe(eventgroup=0x0008, ttl=0xFFFFFF); DUT Acks back
// carrying TTL=0xFFFFFF + Reserved=0 + echoed identity. The
// 0x0008 eventgroup is multicast-configured in vsomeip.json so the
// SubscribeAck path (Ack vs. Nack) reaches the field-echo logic.
template <>
struct TestCaseTraits<cases::SdMessage13SM>
    : SomeIpSdOnlyBase<cases::SdMessage13SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_13";
    static constexpr std::string_view kSpecSection = "5.1.5.3.13";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroupAck echoes Service/Instance/Major/Eventgroup/TTL/Reserved";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0008;
        // 24-bit TTL max — SOMEIP-SD SOMEIPSD §6.7.4.2 "TTL field shall be the
        // same value as in the Subscribe that is being answered"; the
        // pass criterion verifies the DUT echoes this exact value back
        // in the Ack.
        subscribe.ttl = 0xFFFFFF;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe, cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:            return "pass";
            case State::Fail_ack_field:  return "fail:subscribe_ack_field_mismatch";
            case State::Fail_timeout:    return "fail:no_qualifying_sd_message_within_listen_window";
            default:                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage13SM, someipsrv_sd_message_13)
