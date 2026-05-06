#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_format_28_sm.h"

namespace tc8::sce::cases {

using Format28SM =
    ::SCE::Generated::someipsrv_format_28::someipsrv_format_28;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.28 — Eventgroup ID field of the Type 2 entry
// shall carry SdConsumedEventGroupID. Configured identity supplied
// at runtime via --expect eventgroup_id=<hex>; Subscribe stimulus
// echoes the same value in the target so DUT's reply carries it
// regardless of Ack vs Nack path.
template <>
struct TestCaseTraits<cases::Format28SM>
    : SomeIpSdOnlyBase<cases::Format28SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_28";
    static constexpr std::string_view kSpecSection = "5.1.5.1.28";
    static constexpr std::string_view kDescription =
        "Type 2 entry Eventgroup ID shall carry the configured SdConsumedEventGroupID";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // §5.1.5.1.28 exercises the Ack path: subscribe to eventgroup
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
            case State::Pass:                 return "pass";
            case State::Fail_eventgroup_id:   return "fail:entry_eventgroup_id_mismatch";
            case State::Fail_timeout:         return "fail:no_ack_within_listen_window";
            default:                          return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format28SM, someipsrv_format_28)
