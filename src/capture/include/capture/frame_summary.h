#pragma once

#include <cstddef>
#include <cstdint>

#include <pcap/pcap.h>

#include "tc8/frame_summary.h"

namespace tc8::capture {

// Reads the addressing out of one Ethernet frame's headers (DLT_EN10MB; up to two
// VLAN tags). Never reads past `caplen`, so a frame the snaplen cut short yields what
// its captured bytes hold: a frame that is not IPv4 or ARP is a kOther summary with
// no addresses, never an error. `t_us` is left for the caller, which owns the
// timestamp.
//
// A header reader, not a decoder: it is what a passive observer can afford beside the
// capture loop. The protocol-level view of a frame is dissect::PacketPipeline's.
::tc8::FrameSummary summarizeEthernetFrame(const std::uint8_t *data, std::size_t caplen,
                                           std::uint32_t wire_len);

// The same for a pcap record, stamped with the record header's own capture time in
// microseconds since the epoch. `nano` says the header's sub-second field holds
// nanoseconds (the handle's tstampPrecision() is PCAP_TSTAMP_PRECISION_NANO) rather
// than microseconds, so the stamp is in the saved pcap's units either way.
::tc8::FrameSummary summarizePcapRecord(const pcap_pkthdr &hdr, const u_char *bytes, bool nano);

}  // namespace tc8::capture
