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

#include "tcp_acknowledgement_04_neg_sm.h"

namespace tc8::sce::cases {

using TcpAcknowledgement04NegSM =
    ::SCE::Generated::tcp_acknowledgement_04_neg::tcp_acknowledgement_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.18 TCP_ACKNOWLEDGEMENT_04: a conformant DUT receives a pure ACK
// in ESTABLISHED and stays silent (RFC 793 §3.9). kTcpSynthRst makes the lwIP netif input
// hook synthesize the prohibited RST on the connection's 4-tuple when the tester's auto-ACK
// arrives. The fault is armed per-phase — the active OPEN is driven disarmed (the handshake
// SYN,ACK is not a pure ACK and the DUT's third-leg ACK is egress), then armed before the
// DUT data send so only the resulting pure ACK triggers. lwIP-only (kCapIngressFault). The
// first TCP behavioral case reachable via the ingress-synthesis seam (the egress
// field-fault cannot synthesise an emission a conformant DUT never makes).
template <>
struct TestCaseTraits<cases::TcpAcknowledgement04NegSM>
    : TcpIngressFaultNegBase<cases::TcpAcknowledgement04NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_ACKNOWLEDGEMENT_04_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.18";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_ACKNOWLEDGEMENT_04: the lwIP kTcpSynthRst ingress flavor "
        "makes the DUT emit a RST after a pure ACK; a conformant DUT stays silent";

    // Content immaterial — only its arrival makes the tester kernel emit the pure ACK that
    // triggers the synthesis. Same 4 B shape as the positive.
    static constexpr std::array<std::uint8_t, 4> kDutPayload = {
        0xACU, 0xDCU, 0x04U, 0x00U};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpAck04LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpAck04LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) return;

        // Per-phase arm: the handshake has completed (the DUT third-leg ACK is egress, not
        // seen by the input hook), so the synthesis fires only on the tester's auto-ACK of
        // the DUT data sent next.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRst);

        seamSendTcp(dut, open.conn->socket, kDutPayload);

        std::this_thread::sleep_for(std::chrono::seconds(3) +
                                     std::chrono::milliseconds(200));

        dut.tcpControl()->closeTcp(open.conn->socket);
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpAcknowledgement04NegSM, tcp_acknowledgement_04_neg)
