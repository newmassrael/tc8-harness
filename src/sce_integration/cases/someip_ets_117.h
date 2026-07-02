#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_117_sm.h"

namespace tc8::sce::cases {

using SomeipEts117SM = ::SCE::Generated::someip_ets_117::someip_ets_117;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_117 — SubscribeEventgroup with two options of
// the same IPv4 Endpoint type. Per PRS_SOMEIPSD_00393 the DUT MUST Nack OR
// silently ignore. Wire shape: canonical first option + extra IPv4
// Endpoint option in the array (unreferenced; entry's #Opt1 stays 1).
// vsomeip-deviation: `sdi::process_eventgroupentry` accepts the Subscribe
// (uses the first IPv4 Endpoint and silently disregards the second) and
// emits an Ack — strictly non-spec. Verdict is strict: Nack (Type 0x07
// ttl==0) OR silent ignore → pass; Ack (Type 0x07 ttl>0) → fail. Linux
// DUT (vsomeip 3.7.1) therefore lands fail; case is excluded from CI
// green via grep filter in .github/workflows/smoke-test.yml. The
// "duplicate referenced" scenario (both options in `#Opt1=2`) is
// exercised by ETS_173 phase 2 instead.
template <>
struct TestCaseTraits<cases::SomeipEts117SM> : SomeIpAnyBase<cases::SomeipEts117SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_117";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with two same-type (IPv4 Endpoint) options — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // Append a second IPv4 Endpoint option (Type 0x04). Body mirrors
        // the canonical first endpoint structure: IP (4 B) + reserved +
        // l4proto + port = 9 B.
        // Raw wire image: the exact option bytes on the link. The port bytes are
        // kept literal (this IS the wire being asserted) but static_assert-tied to
        // the SD-port SSOT so a kSdPort retune cannot silently diverge from them.
        static_assert((0x77u << 8 | 0x1Au) == tc8::dut::kSdPort,
                      "ets_117 SD port BE bytes (0x77,0x1A) must equal tc8::dut::kSdPort");
        std::vector<std::uint8_t> ipv4_body{
            0xAC, 0x10, 0x00, 0x03,  // 172.16.0.3 (tester)
            0x00,                     // reserved
            0x11,                     // l4proto = UDP
            0x77, 0x1A,               // port = 30490 (BE) — see static_assert above
            0x00                      // reserved tail (option body padding to 9 B)
        };
        params.extra_options.push_back({/*type=*/0x04, /*body=*/std::move(ipv4_body), /*reserved=*/0});
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts117SM, someip_ets_117)
