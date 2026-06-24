#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include <sys/socket.h>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_closing_09_neg_sm.h"

namespace tc8::sce::cases {

using TcpClosing09NegSM = ::SCE::Generated::tcp_closing_09_neg::tcp_closing_09_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.8 TCP_CLOSING_09: a conformant DUT in ESTABLISHED that receives a
// FIN enters CLOSE-WAIT, pure-ACKs it, and stays in CW without emitting a FIN or RST (RFC 793
// §3.5). kTcpSynthRstOnDisruptive makes the lwIP netif input hook synthesize the prohibited RST
// on the connection's 4-tuple when the tester FIN arrives, and the case passes only when that
// synthesized RST is observed (the synth emits a RST, proving the
// dut_emitted_fin_or_rst_in_close_wait fail-final reachable). lwIP-only (kCapIngressFault). The
// DUT stack never sees the synthesized RST (it is a fabricated DUT->tester frame), so the DUT's
// real CLOSE-WAIT behaviour is unchanged. A case the egress field-fault cannot reach.
template <>
struct TestCaseTraits<cases::TcpClosing09NegSM>
    : TcpIngressFaultNegBase<cases::TcpClosing09NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_CLOSING_09_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_CLOSING_09: the lwIP kTcpSynthRstOnDisruptive ingress flavor "
        "makes the DUT emit a RST on entering CLOSE-WAIT; a conformant DUT stays silent";

    // Mirrors the positive's prelude (active-OPEN to ESTABLISHED + tester FIN drives the DUT
    // into CLOSE-WAIT), with the fault armed BEFORE the tester FIN (the disruptive trigger).
    // The arm is given the settle gap before the FIN so the raw-injected arm lands first.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = kTcpClosing09LocalOffset;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) return;

        // Per-phase arm before the tester FIN. The settle gap lets the raw-injected arm reach
        // the DUT UT thread before the kernel-emitted FIN reaches the netif input hook.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);
        std::this_thread::sleep_for(kFlavorArmSettle);

        // Tester FIN: kernel emits FIN+ACK on shutdown(WR). The DUT enters CLOSE-WAIT; the
        // armed hook synthesizes the prohibited RST on the inbound FIN.
        ::shutdown(tester_fd, SHUT_WR);

        std::this_thread::sleep_for(kSynthObserveHold);

        // Silent tester disposal — no tester FIN/RST that could itself confuse the observation.
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing09NegSM, tcp_closing_09_neg)
