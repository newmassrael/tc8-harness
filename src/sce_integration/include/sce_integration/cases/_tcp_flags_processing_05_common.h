#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_config.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

// The body the two iterations of TCP_FLAGS_PROCESSING_05 share. The case asks one question of
// a DUT whose connection is in SYN-RCVD: after an in-window segment, has it gone to LISTEN.
// The wire cannot show a state, so each iteration follows the segment with a verify SYN from
// a different tester source port; a DUT whose LISTEN socket survived answers it with a
// SYN+ACK. The iterations differ in the segment injected into the half-open connection and
// in the port quad that identifies them on the wire, and nothing else, so the sequence is
// written once and the iteration says which segment to inject.

namespace tc8::sce::cases {

// The in-window segment injected into the half-open connection.
enum class FlagsProcessing05Inject {
    // SYN with seq = ISN_t + 1 (in window past SYN consumption).
    kSyn,
    // SYN+ACK with seq = ISN_t + 1 and ack = ISN_d + 1 (an acceptable third-leg ack).
    kSynAck,
};

// One iteration's wire identity: the DUT listen port, the tester source port of the half-open
// connection, and the tester source port of the verify SYN.
struct FlagsProcessing05Ports {
    std::uint16_t listen;
    std::uint16_t prelude_tester;
    std::uint16_t verify_tester;
};

inline constexpr FlagsProcessing05Ports kFlagsProcessing05SynPorts{
    ::tc8::sce::tcp::kBasicsListenPort + 10U,
    ::tc8::sce::tcp::kBasicsTesterPort + 72U,
    ::tc8::sce::tcp::kBasicsTesterPort + 73U,
};

inline constexpr FlagsProcessing05Ports kFlagsProcessing05SynAckPorts{
    ::tc8::sce::tcp::kBasicsListenPort + 11U,
    ::tc8::sce::tcp::kBasicsTesterPort + 74U,
    ::tc8::sce::tcp::kBasicsTesterPort + 75U,
};

inline void flagsProcessing05EmitSyn(const ::tc8::TestConfig& cfg, std::string_view iface,
                                     std::uint16_t src_port, std::uint16_t dst_port,
                                     std::uint32_t seq_value) {
    ::tc8::stimulus::TcpSegmentSpec syn{};
    syn.src_port = src_port;
    syn.dst_port = dst_port;
    syn.seq_num  = seq_value;
    syn.ack_num  = 0U;
    syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
    ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, syn,
                                  /*initial_wait=*/std::chrono::milliseconds(0));
}

inline void flagsProcessing05EmitSynAck(const ::tc8::TestConfig& cfg, std::string_view iface,
                                        std::uint16_t src_port, std::uint16_t dst_port,
                                        std::uint32_t seq_value, std::uint32_t ack_value) {
    ::tc8::stimulus::TcpSegmentSpec sa{};
    sa.src_port = src_port;
    sa.dst_port = dst_port;
    sa.seq_num  = seq_value;
    sa.ack_num  = ack_value;
    sa.flags    = ::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagAck;
    ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, sa,
                                  /*initial_wait=*/std::chrono::milliseconds(0));
}

// Runs in the stimulus, before the listen window:
//   1. seam passive open (driveSeamListen, listen-only) on the listen port.
//   2. TesterAutoRstDrop alive throughout (otherwise the tester kernel auto-RSTs the DUT
//      SYN+ACK landing on the unbound tester source port and the SYN-RCVD socket dies
//      before the spec inject lands).
//   3. Tester SYN at seq = kTesterInitialSeq -> the DUT's SYN+ACK is awaited on the case's
//      own capture -> ISN_d.
//   4. Spec-prescribed inject, per `inject`.
//   5. Verify SYN from a DIFFERENT tester source port. The DUT's LISTEN routes it to a fresh
//      req_sock, so the DUT SYN+ACK on (listen port, verify tester port) lets the machine
//      reach pass.
inline void driveFlagsProcessing05(const ::tc8::TestConfig& cfg,
                                   ::tc8::sce::StimulusContext& ctx,
                                   const FlagsProcessing05Ports& ports,
                                   FlagsProcessing05Inject inject) {
    using namespace ::tc8::sce::tcp;
    const std::string_view iface = ctx.iface;

    if (!driveSeamListen(ctx.dut, ports.listen)) return;

    TesterAutoRstDrop rst_drop(cfg);
    (void)rst_drop;

    const ::tc8::sce::ObservationCursor armed = ctx.observer.mark();

    flagsProcessing05EmitSyn(cfg, iface, ports.prelude_tester, ports.listen, kTesterInitialSeq);

    const auto synack = ctx.observer.awaitObservation(
        "dut_syn_ack", armed, dutSynAckTo(cfg.dut.ip, ports.prelude_tester),
        std::chrono::milliseconds(500));
    if (!synack.has_value()) return;

    switch (inject) {
        case FlagsProcessing05Inject::kSyn:
            // seq = ISN_t + 1 (= rcv_nxt of the DUT after the SYN is consumed). The DUT in
            // SYN-RCVD on (prelude tester port, listen port) sees this; per Linux
            // tcp_check_req it may retx SYN+ACK or refresh the req_sock. LISTEN survives.
            flagsProcessing05EmitSyn(cfg, iface, ports.prelude_tester, ports.listen,
                                     kTesterInitialSeq + 1U);
            break;
        case FlagsProcessing05Inject::kSynAck:
            // seq = ISN_t + 1, ack = ISN_d + 1. Linux tcp_check_req may treat this as the
            // third leg and complete the handshake to ESTABLISHED, or handle it as an
            // anomaly. Either way the LISTEN socket survives: the verify SYN from a
            // different source port still elicits a SYN+ACK.
            flagsProcessing05EmitSynAck(cfg, iface, ports.prelude_tester, ports.listen,
                                        kTesterInitialSeq + 1U,
                                        segmentOf(synack->view()).seq_num + 1U);
            break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Verify LISTEN survived: a fresh SYN from a different tester source port.
    flagsProcessing05EmitSyn(cfg, iface, ports.verify_tester, ports.listen, kTesterInitialSeq);
}

}  // namespace tc8::sce::cases
