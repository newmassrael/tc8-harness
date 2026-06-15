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

#include "someip_ets_137_sm.h"

namespace tc8::sce::cases {

using SomeipEts137SM = ::SCE::Generated::someip_ets_137::someip_ets_137;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_137 — SubscribeEventgroup carrying two
// IPv4 Endpoint options whose individual Length fields are wrong-sized
// (TCP option declares 14 + 5 dummy bytes appended; UDP option declares
// 4 with body truncated) while total OptionsLen + SOME/IP Length stay
// at the canonical 2-option values (24 / 60). Per PRS_SOMEIPSD_00307 /
// 00393 / 00265 / 00274 the DUT must Nack. Lenient verdict accepts
// silent ignore — vsomeip's parser silent-drops on the misaligned
// next-option boundary.
//
// The wire layout is bespoke enough (two options + per-option Length
// override + dummy padding) that we build the datagram inline rather
// than extending `SubscribeEventgroupParams` for a one-off shape.
template <>
struct TestCaseTraits<cases::SomeipEts137SM> : SomeIpAnyBase<cases::SomeipEts137SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_137";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with misaligned 2-option array — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // Wire layout (68 bytes total; SOME/IP Length field = 60 covering
        // bytes from after the Length field through end of frame):
        //   16 B SOME/IP header
        //    4 B SD flags+reserved
        //    4 B EntriesLen = 16
        //   16 B Type 2 entry (#Opt1=2 → walk two options)
        //    4 B OptionsLen = 24
        //   17 B option 1: length=14, IPv4 Endpoint TCP body (9 B) + 5 dummy
        //    7 B option 2: length=4, truncated body (4 B)
        const std::uint32_t tester_ip_be = cfg.ipv4.tester_ip;  // host's veth-tester IPv4 in NBO.
        const std::uint16_t tester_port  = 30490;               // SD port (matches Subscribe response routing).

        std::vector<std::uint8_t> d;
        d.reserve(68);

        auto putBe16 = [&d](std::uint16_t v) {
            d.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
            d.push_back(static_cast<std::uint8_t>(v & 0xFF));
        };
        auto putBe24 = [&d](std::uint32_t v) {
            d.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
            d.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
            d.push_back(static_cast<std::uint8_t>(v & 0xFF));
        };
        auto putBe32 = [&d](std::uint32_t v) {
            d.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
            d.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
            d.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
            d.push_back(static_cast<std::uint8_t>(v & 0xFF));
        };

        // SOME/IP header.
        putBe16(0xFFFF);    // service_id (SD)
        putBe16(0x8100);    // method_id (SD)
        putBe32(60U);       // Length field = 60 (8 RID-tail + 52 payload)
        putBe16(0x0000);    // client_id
        putBe16(0x0001);    // session_id
        d.push_back(0x01);  // proto_ver
        d.push_back(0x01);  // iface_ver
        d.push_back(0x02);  // msg_type = NOTIFICATION
        d.push_back(0x00);  // return_code

        // SD header: flags + 24-bit reserved.
        d.push_back(0xC0);  // Reboot=1 Unicast=1
        putBe24(0);

        // EntriesLen.
        putBe32(16U);

        // Type 2 SubscribeEventgroup entry (16 B). #Opt1 = 2 (two options
        // in run 1), #Opt2 = 0. ServiceID = 0xF4E7, InstanceID = 0x0001,
        // Major = 1, TTL = 3 s, Counter = 0, EventgroupID = 0x0001.
        d.push_back(0x06);  // Type = SubscribeEventgroup
        d.push_back(0x00);  // IndexFirstOptionRun
        d.push_back(0x00);  // IndexSecondOptionRun
        d.push_back(0x20);  // #Opt1=2 | #Opt2=0
        putBe16(0xF4E7);
        putBe16(0x0001);
        d.push_back(0x01);
        putBe24(3U);
        d.push_back(0x00);  // Reserved (12b high)
        d.push_back(0x00);  // Reserved (4b) | Counter (4b) = 0
        putBe16(0x0001);

        // OptionsLen.
        putBe32(24U);

        // Option 1: TCP-flavoured IPv4 Endpoint with Length=14 + 5 dummy.
        // Total physical: 2 (length) + 1 (type) + 14 (body) = 17 B.
        putBe16(14U);       // Length field (declares 14 body bytes)
        d.push_back(0x04);  // Type = IPv4 Endpoint
        d.push_back(0x00);  // Reserved
        d.push_back(static_cast<std::uint8_t>(tester_ip_be & 0xFF));
        d.push_back(static_cast<std::uint8_t>((tester_ip_be >> 8) & 0xFF));
        d.push_back(static_cast<std::uint8_t>((tester_ip_be >> 16) & 0xFF));
        d.push_back(static_cast<std::uint8_t>((tester_ip_be >> 24) & 0xFF));
        d.push_back(0x00);  // Reserved
        d.push_back(0x06);  // L4-Proto = TCP
        putBe16(tester_port);
        for (int i = 0; i < 5; ++i) d.push_back(0xCC);  // 5 dummy padding bytes

        // Option 2: UDP-flavoured IPv4 Endpoint with Length=4 (truncated).
        // Total physical: 2 (length) + 1 (type) + 4 (body) = 7 B.
        putBe16(4U);        // Length field (declares 4 body bytes)
        d.push_back(0x04);  // Type = IPv4 Endpoint
        d.push_back(0x00);  // Reserved
        d.push_back(static_cast<std::uint8_t>(tester_ip_be & 0xFF));
        d.push_back(static_cast<std::uint8_t>((tester_ip_be >> 8) & 0xFF));
        d.push_back(static_cast<std::uint8_t>((tester_ip_be >> 16) & 0xFF));

        // sendSdUnicast binds to SD source port 30490 internally so vsomeip
        // does not silent-drop on the "Ignored SD message from unknown
        // port" gate; destination defaults to the tc8-dut SD endpoint
        // (172.16.0.2 : 30490).
        constexpr std::uint32_t kDutIpBe = 0x020010ACu;
        ::tc8::stimulus::sendSdUnicast(d, iface, kDutIpBe);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts137SM, someip_ets_137)
