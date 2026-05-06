#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_format_19_sm.h"

namespace tc8::sce::cases {

using Format19SM =
    ::SCE::Generated::someipsrv_format_19::someipsrv_format_19;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.19 — Type field of the Type 2 Entry shall be 0x07
// for SubscribeEventgroupAck / Nack. Verified after the harness
// stimulates with a SubscribeEventgroup (0x06).
template <>
struct TestCaseTraits<cases::Format19SM>
    : SomeIpSdOnlyBase<cases::Format19SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_19";
    static constexpr std::string_view kSpecSection = "5.1.5.1.19";
    static constexpr std::string_view kDescription =
        "Type 2 entry Type shall be 0x07 (SubscribeEventgroupAck or Nack)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // §5.1.5.1.19 exercises the Ack path: subscribe to eventgroup
        // 0x0002 (declared under TestEventUINT8 in dut/ets/ets.fdepl +
        // dut/dut_service/vsomeip.json) so DUT replies with
        // SubscribeEventgroupAck (TTL > 0) instead of Nack (TTL = 0).
        // The Type 2 entry-format invariants verified by FORMAT_19..28
        // are identical for Ack and Nack; running the Ack path
        // exercises the spec's primary case and the harness's
        // configured TTL value.
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe,
                                                     cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:            return "pass";
            case State::Fail_timeout:    return "fail:no_ack_within_listen_window";
            default:                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format19SM, someipsrv_format_19)
