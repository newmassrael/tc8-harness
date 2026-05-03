#pragma once

#include <cstdint>

namespace tc8::dissect {

struct Transport {
    enum class Proto : std::uint8_t { Udp, Tcp };

    Proto proto;
    std::uint32_t src_ip;
    std::uint32_t dst_ip;
    std::uint16_t src_port;
    std::uint16_t dst_port;

    // pcap arrival timestamp for this datagram, normalised to
    // microseconds by `PacketPipeline::processFrame`. Carried through
    // to `SomeIpFrame::observed_ts_us` via `SomeIpDispatcher::makeFrame`
    // so SOMEIPSRV §5.1.5.4 SD_BEHAVIOR_01/_02 can read inter-frame gaps
    // out of `SomeIpCaptured::frame_delta_us()`. Defaults to 0 for the
    // TCP follower path (reassembled streams have no single per-message
    // pcap timestamp); UDP datagram path always populates it.
    std::int64_t observed_ts_us = 0;
};

inline const char *protoName(Transport::Proto p) {
    switch (p) {
    case Transport::Proto::Udp:
        return "UDP";
    case Transport::Proto::Tcp:
        return "TCP";
    }
    return "???";
}

}  // namespace tc8::dissect
