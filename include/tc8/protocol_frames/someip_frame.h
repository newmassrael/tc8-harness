#pragma once

#include <cstdint>

namespace tc8 {

// Decoded SOME/IP message as it appears on the wire, carried inside
// CapturedEvent. The pointer into `payload_data` is valid only for the
// duration of the ITestRunner::onCaptured() call — dispatch copies out
// whatever it needs before returning.
//
// Corresponds to TC8 v3.0 §5.1 test-case fields (service/method/client/
// session IDs, proto/iface version, message type, return code, length,
// payload) plus the encapsulating transport endpoints.
struct SomeIpFrame {
    // Transport (from the encapsulating UDP datagram or TCP segment).
    std::uint32_t src_ip = 0;
    std::uint32_t dst_ip = 0;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    bool          is_tcp = false;

    // SOME/IP header fields (§5.1.4).
    std::uint16_t service_id        = 0;
    std::uint16_t method_id         = 0;
    std::uint32_t length            = 0;
    std::uint16_t client_id         = 0;
    std::uint16_t session_id        = 0;
    std::uint8_t  protocol_version  = 0;
    std::uint8_t  interface_version = 0;
    std::uint8_t  message_type      = 0;
    std::uint8_t  return_code       = 0;

    // Payload region (not owning).
    const std::uint8_t* payload_data = nullptr;
    std::uint32_t       payload_len  = 0;

    // pcap arrival timestamp, microseconds (host-time). Plumbed from
    // `PacketPipeline::processFrame` through `Transport::observed_ts_us`
    // and `SomeIpDispatcher::makeFrame`. Surfaced into
    // `SomeIpCaptured::observed_ts_us` so §5.1.5.4 SD_BEHAVIOR_01/_02
    // timing cases can read inter-frame gaps via `frame_delta_us()`.
    // Defaults to 0 for the TCP-stream-reassembly path (no single
    // per-message timestamp); UDP datagram path always populates it.
    std::int64_t observed_ts_us = 0;
};

}  // namespace tc8
