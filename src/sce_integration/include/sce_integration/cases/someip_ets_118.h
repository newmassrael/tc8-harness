#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_118_sm.h"

namespace tc8::sce::cases {

using SomeipEts118SM = ::SCE::Generated::someip_ets_118::someip_ets_118;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_118 — Tester sends 10 multicast FindService
// messages, each carrying one IPv4 Endpoint option in its Options Array
// (entry's #Opt1=0 — option is physically present but UNREFERENCED). Per
// PRS_SOMEIPSD_00268 / SIP_SD_877 / SIP_SD_878 the DUT shall ignore the
// option and respond with at least one OfferService for SERVICE-ID-1.
template <>
struct TestCaseTraits<cases::SomeipEts118SM> : SomeIpAnyBase<cases::SomeipEts118SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_118";
    static constexpr std::string_view kDescription =
        "FindService with unreferenced IPv4 Endpoint option (×10) — DUT ignores option, OfferServices";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));

        ::tc8::stimulus::Ipv4Endpoint endpoint{};
        endpoint.ipv4_be = 0x030010ACU;  // 172.16.0.3 (tester veth)
        endpoint.port = tc8::dut::kSdPort;
        endpoint.l4proto = 0x11;  // UDP

        for (std::uint16_t sid = 0x0001; sid <= 0x000A; ++sid) {
            ::tc8::stimulus::FindServiceParams p{};
            p.session_id = sid;
            p.sd_flags = 0xC0;
            const auto datagram = ::tc8::stimulus::buildFindServiceWithOption(p, endpoint);
            ::tc8::stimulus::sendSdMulticast(datagram, iface);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts118SM, someip_ets_118)
