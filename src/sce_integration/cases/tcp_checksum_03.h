#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_checksum_03_sm.h"

namespace tc8::sce::cases {

using TcpChecksum03SM = ::SCE::Generated::tcp_checksum_03::tcp_checksum_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpChecksum03SM>
    : TcpAnyBase<cases::TcpChecksum03SM> {
    static constexpr std::string_view kCaseId       = "TCP_CHECKSUM_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.2";
    static constexpr std::string_view kDescription  =
        "Sender TCP MUST generate a correct RFC 793 §3.1 pseudo-header "
        "checksum (RFC 1122 §4.2.2.7 p86 TCP Checksum)";

    // Spec Test Procedure (v3.0 p301-p320.txt:194):
    //   1. TESTER: Cause DUT ESTABLISHED — UT OpOpenTcpSocket(Active).
    //   2. TESTER: Cause DUT-side application SEND — UT OpSendTcpData.
    //   3. DUT:    Send the data segment.
    //   4. TESTER: Verify checksum is correct (SCXML pass guard reads
    //              captured.tcp_checksum_valid()).
    //
    // Same active-OPEN scaffold as BASICS_06+: the tester arms an
    // auxiliary listener so DUT's connect() lands on a real receiver
    // and the kernel completes the 3-way handshake. Once ESTABLISHED,
    // the UT OpSendTcpData request flushes a small fixed payload
    // through tc8-dut's accepted_fd; Linux frames the bytes into
    // one DATA segment whose checksum SCXML observes.
    //
    // The 4 B payload is small enough to fit in a single segment on
    // any sane MTU but non-empty so payload_len > 0 in the SCXML
    // distinguishes the spec-asserted DATA segment from the handshake
    // ACK that precedes it. Content is opaque to the spec — the
    // assertion is on the checksum, not the bytes.
    static constexpr std::array<std::uint8_t, 4> kChecksumPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1,
            kBasicsActiveLocalPort  + kTcpChecksum03LocalOffset,
            kBasicsActiveRemotePort + kTcpChecksum03LocalOffset);
        (void)listener;

        // OpSendTcpData runs through the same UT RPC channel as
        // OpenTcp; the tc8-dut writes the bytes synchronously inside
        // the UT server loop, so a single kTcpUtRpcWait is enough for
        // the DATA segment to land on the wire before the SCXML's
        // listen window expires.
        sendSendTcpDataRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1,
            kChecksumPayload.data(),
            static_cast<std::uint16_t>(kChecksumPayload.size()));
        std::this_thread::sleep_for(kTcpUtRpcWait);

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/3, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_bad_checksum:   return "fail:dut_emitted_segment_with_invalid_checksum";
            case State::Fail_timeout:        return "fail:no_dut_data_segment_within_listen_window";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpChecksum03SM, tcp_checksum_03)
