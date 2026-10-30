#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_config.h"
#include "stimulus/tcp_segment_builder.h"

// What the three iterations of TCP_CALL_RECEIVE_04 share. The case asks one question of a DUT
// holding queued segments: does a RECEIVE with a buffer larger than the run come back with
// the bytes joined in order. The iterations differ in the state the DUT is in when the data
// arrives, and in how the tester walks it there, so each iteration keeps its own stimulus;
// the run of segments injected and the grade of the answer are the same and live here.

namespace tc8::sce::cases {

// 4 segments x 32 bytes = 128 bytes total per iteration. Stays well under kMaxPayload (256)
// so the single UT recv response carries every byte without splitting; large enough that
// reassembly is not trivially "one segment delivered as one segment".
inline constexpr std::uint16_t kCallReceive04SegmentSize = 32U;
inline constexpr std::uint16_t kCallReceive04SegmentCount = 4U;
inline constexpr std::uint16_t kCallReceive04PayloadLen =
    kCallReceive04SegmentSize * kCallReceive04SegmentCount;

// What an iteration's RECEIVE answered, for its SCXML: kCallReceive04PayloadLen when it
// returned the reassembled stream; 0 when the DUT answered anything else, a refusal included
// (it did not return the data, observed_violation); the 0xFFFF sentinel when no answer came
// (inconclusive; the decorator records it as an unperformed stimulus).
inline std::uint16_t gradeCallReceive04(const ::tc8::sce::DutReceiveOutcome &received,
                                        const std::vector<std::uint8_t> &expected) {
    if (!received.answered()) {
        return 0xFFFFU;
    }
    return received.returned(expected) ? kCallReceive04PayloadLen : 0U;
}

// Inject N consecutive small data segments with seq advancing by kCallReceive04SegmentSize
// per segment. `ack_value` stays constant per iteration: in FIN-WAIT-1 it is a non-acking ack
// (= snd.una of the DUT, which does not ack the FIN); in ESTABLISHED and FIN-WAIT-2 it acks
// the third-leg / the DUT FIN respectively. The pattern byte distinguishes the iteration's
// output in the pcap.
inline std::vector<std::uint8_t> injectCallReceive04Segments(const ::tc8::TestConfig &cfg,
                                                             std::string_view iface,
                                                             std::uint16_t src_port,
                                                             std::uint16_t dst_port,
                                                             std::uint32_t seq_base,
                                                             std::uint32_t ack_value,
                                                             std::uint8_t pattern) {
    std::vector<std::uint8_t> total;
    total.reserve(kCallReceive04PayloadLen);
    for (std::uint16_t i = 0U; i < kCallReceive04SegmentCount; ++i) {
        std::vector<std::uint8_t> chunk(kCallReceive04SegmentSize,
                                        static_cast<std::uint8_t>(pattern + i));
        ::tc8::stimulus::TcpSegmentSpec seg{};
        seg.src_port = src_port;
        seg.dst_port = dst_port;
        seg.seq_num = seq_base + (i * kCallReceive04SegmentSize);
        seg.ack_num = ack_value;
        seg.flags = ::tc8::stimulus::kTcpFlagAck | ::tc8::stimulus::kTcpFlagPsh;
        seg.payload = chunk;
        ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, seg,
                                      /*initial_wait=*/std::chrono::milliseconds(0));
        total.insert(total.end(), chunk.begin(), chunk.end());
        // Tiny gap between segments: keeps Linux from coalescing them in the receive queue
        // before the application reads; either coalescing or non-coalescing is
        // RFC-conformant (the spec asserts only on the reassembled buffer the application
        // sees), so the gap is conservative.
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return total;
}

}  // namespace tc8::sce::cases
