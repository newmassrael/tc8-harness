#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "tc8/captured_event.h"

// Protocol-presentation layer for the `tc8-harness decode-pcap` exporter
// (docs/tech-debt.md TD-08). Owns the per-protocol human-readable summary
// builders and the per-frame candidate selection that turn a decoded
// CapturedEvent into the documentation site's "protocol" + "summary" row text.
//
// Extracted from the decode-pcap command translation unit so the presentation
// logic is unit-testable in isolation (unit_tests/packet_summary_test.cpp) and
// reusable by any future text renderer (e.g. a live/replay view). The command
// TU keeps only JSON assembly, endpoint auto-detection, and the offline drive
// loop. The numeric display-name tables and formatting helpers stay private to
// packet_summary.cpp; only the frame-typed builders are exposed here.

namespace tc8::cli {

// Per-protocol one-line human summaries (mirror the labels the retired
// site/scripts/decode_pcap.py emitted so the rendered timeline text is stable).
std::string arpSummary(const ::tc8::ArpFrame &f);
std::string icmpSummary(const ::tc8::Icmpv4Frame &f);
std::string dhcpSummary(const ::tc8::Dhcpv4Frame &f);
std::string tcpSummary(const ::tc8::TcpFrame &f);
std::string udpSummary(const ::tc8::UdpFrame &f);
std::string someipSummary(const ::tc8::SomeIpFrame &f);
std::string sdSummary(const ::tc8::SomeIpFrame &f);

// UT request/response carried in a kPort UDP datagram, decoded through the
// shared tc8::ut::decodeResponse (docs/tech-debt.md TD-06).
std::string utSummary(const std::uint8_t *payload, std::uint32_t len);

// True when a SOME/IP header is a Service Discovery message (Message ID magic
// routed through someip::isSdMessageId, NOTIFICATION + E_OK).
bool someipIsSd(const ::tc8::SomeIpFrame &f);

// One decoded-protocol view of a frame. The pipeline emits a variant per layer
// (Ipv4Frame + UdpFrame + SomeIpFrame, etc.); the candidate with the highest
// `prio` is the deepest / most specific and wins the row.
struct Candidate {
    int prio = 0;
    std::string protocol;
    std::string summary;
    std::optional<std::uint32_t> src_ip;
    std::optional<std::uint32_t> dst_ip;
};

// Build a candidate from one pipeline event. IMPORTANT: this MUST run while the
// event's non-owning `payload_data` still points at the live frame buffer (it
// dangles once the pipeline's processFrame returns). UT is presentation-decoded
// from the UDP payload here because the pipeline (verdict path) has no UT event.
Candidate makeCandidate(const ::tc8::CapturedEvent &ev);

// The chosen protocol/summary/endpoints for one frame. protocol defaults to
// "UNKNOWN" and summary to "" so a frame the pipeline could not decode renders
// as UNKNOWN rather than a synthesized label.
struct FrameView {
    std::string protocol = "UNKNOWN";
    std::string summary;
    std::optional<std::uint32_t> src_ip;
    std::optional<std::uint32_t> dst_ip;
};

// Pick the deepest (highest-prio) candidate for a frame, or synthesize the
// raw-Ethernet fallback label when the pipeline emitted nothing (non-IP/non-ARP
// ethertype such as IPv6, or a frame too short/malformed to parse). Owns the
// per-frame selection + fallback presentation so the command TU keeps only I/O.
FrameView chooseFrameView(const std::vector<Candidate> &candidates,
                          std::uint16_t ethertype, std::uint32_t caplen);

}  // namespace tc8::cli
