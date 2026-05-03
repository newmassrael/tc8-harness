#pragma once

#include <cstdint>

namespace tc8 {

// RFC 793 TCP header plus encapsulating IPv4 endpoints. TC8 §4.8 covers
// BASICS (state transitions), FLAGS_INVALID, CONTROL_FLAGS, UNACCEPTABLE
// segments, MSS_OPTIONS, RETRANSMISSION_TIMEOUT, OUT_OF_ORDER, etc. — so
// both the per-segment header view and the parsed MSS option are exposed.
// Longer option parsing (SACK, Timestamp, Window Scale) is deferred to
// per-case dispatch via `options_data`.
struct TcpFrame {
    std::uint32_t src_ip   = 0;
    std::uint32_t dst_ip   = 0;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint32_t seq_num  = 0;
    std::uint32_t ack_num  = 0;
    std::uint8_t  data_offset = 0;  // header length in 32-bit words
    std::uint8_t  flags       = 0;  // CWR ECE URG ACK PSH RST SYN FIN
    std::uint16_t window         = 0;
    std::uint16_t checksum       = 0;
    std::uint16_t urgent_pointer = 0;

    // RFC 793 kind=2 MSS option; 0 if the segment didn't advertise one.
    std::uint16_t mss = 0;

    const std::uint8_t* options_data = nullptr;
    std::uint32_t       options_len  = 0;
    const std::uint8_t* payload_data = nullptr;
    std::uint32_t       payload_len  = 0;

    // RFC 793 §3.1 pseudo-header checksum validation result, computed
    // at decode time over (src_ip + dst_ip + zero + protocol +
    // tcp_length) ‖ TCP header ‖ options ‖ payload. True iff the
    // one's-complement sum collapses to 0xFFFF — the same invariant
    // tcp_segment_builder upholds when constructing valid segments.
    // §4.8.6.2 TCP_CHECKSUM_03 reads this through a `TcpCaptured`
    // method to assert the DUT's sender-side checksum compute path.
    bool checksum_valid = false;

    // Wall-clock arrival timestamp of the captured frame in
    // microseconds since the Unix epoch, sourced from
    // `pcap_pkthdr::ts` and normalised on the dissect side
    // (`PacketPipeline::processFrame` divides by 1000 when the
    // source uses `PCAP_TSTAMP_PRECISION_NANO`). The only
    // wire-observable surface for inter-frame timing assertions —
    // §4.8.6.11 RETRANSMISSION_TO_03/_04/_05/_06 use this (mirrored
    // into `TcpCaptured.observed_ts_us`) to gate on RFC 6298 RTO=1 s,
    // exponential-backoff "more-than-linear" deltas, and Karn's
    // doubling preservation across acknowledgement-after-retransmit;
    // §4.8.6.12 PROBING_WINDOWS_06 verifies zero-window-probe
    // interval doubling.
    std::int64_t observed_ts_us = 0;
};

}  // namespace tc8
