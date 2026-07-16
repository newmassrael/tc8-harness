#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "tc8/autosar/someiptp.h"

namespace tc8::stimulus {

// Emit `payload` (the application data of one SOME/IP message) as SOME/IP-TP segments
// to `dst_ip_be`:`dst_port` over `iface`, each segment a UDP datagram from `src_port`.
// someiptp::Segmenter frames the segments (the single source of the TP wire format);
// this only adds the tester-side transmit, sending each via sendUdpUnicast. It is how a
// tester drives the DUT's TP reassembly (e.g. a segmented Request the DUT must reassemble).
//
// `max_segment_payload` is the per-non-last-segment payload cap (a non-zero multiple of
// 16; default the spec-recommended 1392). `reserved` sets the TP header's 3 Reserved
// bits on every segment (default 0 = conformant; non-zero drives the "receiver must
// ignore Reserved" negative). Returns 0 when every segment was
// sent, or the first negative sendUdpUnicast sentinel on failure (remaining segments are
// not sent). Propagates the Segmenter's exceptions on a bad max_segment_payload or an
// over-long payload (see someiptp::Segmenter).
int emitSomeIpTpSegments(std::string_view iface, std::uint16_t src_port,
                         const someiptp::MessageHeader &hdr, const std::uint8_t *payload,
                         std::size_t len, std::uint32_t dst_ip_be, std::uint16_t dst_port,
                         std::size_t max_segment_payload = someiptp::kRecommendedMaxSegment,
                         std::uint8_t reserved = 0);

}  // namespace tc8::stimulus
