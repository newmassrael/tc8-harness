#pragma once

#include <cstdint>

namespace tc8 {

// The addressing of one captured Ethernet frame, as far as its headers go: enough to
// draw "who sent what to whom, when", and nothing of what the frame carries.
//
// Deliberately a plain-data leaf carrying NO libpcap types, like CaptureStats: it
// crosses from the capture layer (which parses) to the live state stream (which
// writes it), and the latter must not acquire a libpcap dependency to print a number.
struct FrameSummary {
    enum class Proto { kOther, kUdp, kTcp };

    // Kernel capture time, microseconds since the Unix epoch: the clock and the
    // precision of the saved pcap's own record header.
    std::int64_t t_us = 0;
    // Length on the wire (the record's original length), not the captured part.
    std::uint32_t wire_len = 0;

    Proto proto = Proto::kOther;

    // IPv4 addresses, network byte order (first octet lowest in memory, as in
    // TxEvent::dst_ip_be). For an IPv4-over-Ethernet ARP they are the sender and
    // target protocol addresses; the proto stays kOther.
    bool          has_ips   = false;
    std::uint32_t src_ip_be = 0;
    std::uint32_t dst_ip_be = 0;

    // UDP/TCP ports, host order. Absent when the transport header is not in the
    // captured bytes (a non-first fragment, or a frame cut short by the snaplen).
    bool          has_ports = false;
    std::uint16_t src_port  = 0;
    std::uint16_t dst_port  = 0;
};

}  // namespace tc8
