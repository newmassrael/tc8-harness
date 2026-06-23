#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_header_01_neg_sm.h"

namespace tc8::sce::cases {

using TcpHeader01NegSM = ::SCE::Generated::tcp_header_01_neg::tcp_header_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpHeader01NegSM>
    : TcpEgressFaultNegBase<cases::TcpHeader01NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_01_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_HEADER_01's checksum conjunct: the lwIP "
        "kTcpFaultDataChecksumWrong egress flavor invalidates the DUT data-segment "
        "checksum; a conformant DUT emits a valid one (the data_offset conjunct is "
        "unreachable through the libtins dissector — see README)";

    // Same fixed payload the positive sends — opaque to the spec (the assertion is on
    // header validity), non-empty so payload_len > 0 selects the DATA segment.
    static constexpr std::array<std::uint8_t, 4> kHeaderPayload = {
        0xCAU, 0xFEU, 0xBAU, 0xBEU};

    // Arm the data-segment checksum fault, then drive the same active OPEN + SEND the
    // positive uses. The flavor is payload-gated, so the handshake's control segments
    // keep valid checksums and the connection reaches ESTABLISHED; the DUT's DATA
    // segment is emitted with an XOR-invalidated checksum — the violation the positive
    // forbids — and captured via pcap regardless of the bad checksum.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultDataChecksumWrong);

        auto open = driveSeamActiveOpen(
            dut, cfg,
            kBasicsActiveLocalPort  + kTcpHeader01LocalOffset,
            kBasicsActiveRemotePort + kTcpHeader01LocalOffset);

        if (open.conn) {
            seamSendTcp(dut, open.conn->socket, kHeaderPayload);
            dut.tcpControl()->closeTcp(open.conn->socket);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader01NegSM, tcp_header_01_neg)
