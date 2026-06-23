#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_144_sm.h"

namespace tc8::sce::cases {

using SomeipEts144SM = ::SCE::Generated::someip_ets_144::someip_ets_144;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_144 — SubscribeEventgroup whose IPv4
// Endpoint option carries non-zero reserved bytes (canonical 0x00 at
// offset 3 + offset 8 inside the 12-byte option). Per
// PRS_SOMEIPSD_00307 / 00391 the DUT must ignore the reserved fields
// and Ack. Lenient positive verdict accepts Ack OR silent ignore;
// Nack lands fail.
template <>
struct TestCaseTraits<cases::SomeipEts144SM> : SomeIpAnyBase<cases::SomeipEts144SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_144";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup IPv4 Endpoint option reserved bytes set — DUT Acks (ignores reserved)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        // Configured eventgroup so a clean Ack can land if the DUT
        // really does ignore the reserved bytes.
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // Spec wording: "reserved Fields of the Endpoint Options set".
        // Two reserved bytes inside the IPv4 Endpoint option: byte 3
        // (immediately after Type) and byte 8 (between IPv4 and L4-Proto).
        params.option_reserved0_override = std::uint8_t{0xFF};
        params.option_reserved1_override = std::uint8_t{0xFF};
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts144SM, someip_ets_144)
