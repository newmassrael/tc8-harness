#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_header_01_sm.h"

namespace tc8::sce::cases {

using TcpHeader01SM = ::SCE::Generated::tcp_header_01::tcp_header_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpHeader01SM>
    : TcpAnyBase<cases::TcpHeader01SM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_01";
    static constexpr std::string_view kSpecSection  = "4.8.6.X";
    static constexpr std::string_view kDescription  =
        "DUT generates a TCP packet containing valid header field values "
        "(RFC 793 §3.1 Header Format)";

    static constexpr std::array<std::uint8_t, 4> kHeaderPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Spec Test Procedure (v3.0 p385):
    //   1. Tester brings DUT to ESTABLISHED — driveActiveOpenEstablished.
    //   2. Tester triggers <generateTCPSegment> — UT OpSendTcpData.
    //   3. DUT emits the data segment; SCXML asserts header validity.
    //
    // Same scaffold as CHECKSUM_03 with a stricter pass guard
    // (data_offset >= 5 in addition to checksum_valid). The DATA-only
    // payload_len > 0 disambiguator distinguishes the spec-asserted
    // segment from the handshake third-leg ACK that egressed first.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 30U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 30U;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1, local_port, remote_port);
        (void)listener;

        sendSendTcpDataRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1,
            kHeaderPayload.data(),
            static_cast<std::uint16_t>(kHeaderPayload.size()));
        std::this_thread::sleep_for(kTcpUtRpcWait);

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/3, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:               return "pass";
            case State::Fail_bad_header:    return "fail:dut_emitted_segment_with_invalid_header";
            case State::Fail_timeout:       return "fail:no_dut_data_segment_within_listen_window";
            default:                        return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader01SM, tcp_header_01)
