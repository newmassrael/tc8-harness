#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>

#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_config.h"
#include "stimulus/tcp_segment_builder.h"

// What the iterations of TCP_FLAGS_PROCESSING_08 share. The case asks one question of a DUT that
// is not synchronised (CLOSED, LISTEN, SYN-SENT): given a bare FIN, does it leave the segment
// unprocessed. The iterations differ in the state the DUT is in, which is also what each needs
// of the DUT's control interface, so the stimulus around the FIN is written by each iteration and
// only the FIN and the ports are held here.

namespace tc8::sce::tcp {

// The LISTEN iteration's wire identity: a passive listener, and the tester port the FIN comes
// from. They sit clear of FLAGS_INVALID_07's +0..+4 listen reservation.
inline constexpr std::uint16_t kTcpFlagsProcessing08ListenPort = kBasicsListenPort + 14U;
inline constexpr std::uint16_t kTcpFlagsProcessing08ListenTesterPort = kBasicsTesterPort + 71U;

}  // namespace tc8::sce::tcp

namespace tc8::sce::cases {

// A FIN with no other control bit, the segment every iteration injects.
inline void emitBareFin(const ::tc8::TestConfig &cfg, std::string_view iface,
                        std::uint16_t src_port, std::uint16_t dst_port) {
    ::tc8::stimulus::TcpSegmentSpec fin{};
    fin.src_port = src_port;
    fin.dst_port = dst_port;
    fin.seq_num = ::tc8::sce::tcp::kTesterInitialSeq;
    fin.ack_num = 0U;
    fin.flags = ::tc8::stimulus::kTcpFlagFin;
    ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, fin,
                                  /*initial_wait=*/std::chrono::milliseconds(0));
}

}  // namespace tc8::sce::cases
