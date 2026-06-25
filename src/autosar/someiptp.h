#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <vector>

namespace tc8::someiptp {

// AUTOSAR SOME/IP base header fields (PRS_SOMEIP §4.1.2), carried big-endian on the
// wire. The public SOME/IP base header is also modeled by tc8::dissect::SomeIpHeader;
// this engine re-declares the few constants/fields it needs ON PURPOSE so it stays a
// dependency-light static lib that compiles into tc8-lwip-utm via the src/autosar/*.cpp
// glob without pulling in src/dissect. The duplicated values (16-byte header, TP flag
// 0x20) are frozen public protocol facts, not config that can drift.
//
// Every value is caller-supplied transported identity — Service / Method / Client /
// Session ids are OEM values passed per message, never baked in. Session ID uniqueness
// per original message (PRS_SOMEIP_00720, Session Handling) is the caller's
// responsibility; the engine carries the Session ID (the low 16 bits of request_id)
// verbatim and keys reassembly on it (PRS_SOMEIP_00721 / 00731). Length is derived from
// the payload, not stored.
struct MessageHeader {
    std::uint32_t message_id = 0;        // Service ID (hi 16) | Method/Event ID (lo 16)
    std::uint32_t request_id = 0;        // Client ID (hi 16) | Session ID (lo 16)
    std::uint8_t  protocol_version = 0;
    std::uint8_t  interface_version = 0;
    std::uint8_t  message_type = 0;      // base type; the engine sets the TP-flag per segment
    std::uint8_t  return_code = 0;
};

// Fixed header sizes in bytes — SOME/IP header (PRS_SOMEIP §4.1.2) and TP header
// (PRS_SOMEIP §4.2.1.4, Table 4.8).
inline constexpr std::size_t kSomeipHeaderLen = 16;  // Message ID .. Return Code
inline constexpr std::size_t kTpHeaderLen = 4;       // Offset | Reserved | More-Segments
inline constexpr std::size_t kSegmentHeaderLen = kSomeipHeaderLen + kTpHeaderLen;  // 20

// Bytes of the SOME/IP header the Length field covers: Request ID .. Return Code
// (PRS_SOMEIP_00728). A segment's wire Length is this + the TP header + the segment.
inline constexpr std::size_t kLengthCoveredHeaderBytes = 8;

// TP-Flag bit OR'd into the Message Type of every segment (PRS_SOMEIP_00722, Table 4.11).
inline constexpr std::uint8_t kMessageTypeTpFlag = 0x20;

// The Offset field holds the upper 28 bits of a byte offset, so offsets and all
// non-last segment lengths are multiples of 16 (PRS_SOMEIP_00724 / 00729).
inline constexpr std::size_t kOffsetGranularity = 16;

// Largest byte offset the 28-bit Offset field can address: (2^28 - 1) * 16
// (PRS_SOMEIP_00724). A payload whose last segment would start beyond this cannot be
// represented and is rejected by the Segmenter.
inline constexpr std::size_t kMaxByteOffset = ((std::size_t{1} << 28) - 1) * kOffsetGranularity;

// Recommended (advisory, not mandatory) maximum segment payload (PRS_SOMEIP_00730).
inline constexpr std::size_t kRecommendedMaxSegment = 1392;

// Splits a SOME/IP message payload into SOME/IP-TP segments (PRS_SOMEIP §4.2.1.4).
// Stateless wire framing only; the owning module transmits each returned buffer.
class Segmenter {
public:
    // max_segment_payload = payload bytes per non-last segment. Must be a non-zero
    // multiple of kOffsetGranularity (PRS_SOMEIP_00724 / 00729). The spec's 1392
    // (kRecommendedMaxSegment) is advisory, so larger 16-multiples are allowed; the
    // only hard cap is that a segment's wire Length must fit its uint32 field. Throws
    // std::invalid_argument otherwise.
    explicit Segmenter(std::size_t max_segment_payload);

    // Build the on-wire SOME/IP-TP segments for `payload`: each frame is the 16-byte
    // SOME/IP header + 4-byte TP header + segment bytes, with Length, the Message-Type
    // TP-flag, Offset and More-Segments set per the spec and the remaining header
    // fields copied from `hdr`. A payload that fits in one segment yields a single
    // segment with More-Segments = 0. Throws std::invalid_argument if payload is null
    // while len != 0, or std::length_error if `len` exceeds the 28-bit Offset field
    // (kMaxByteOffset).
    std::vector<std::vector<std::uint8_t>> segment(const MessageHeader& hdr,
                                                   const std::uint8_t* payload,
                                                   std::size_t len) const;

    std::size_t maxSegmentPayload() const { return max_segment_payload_; }

private:
    std::size_t max_segment_payload_;
};

// Reassembles received SOME/IP-TP segments back into original messages. Holds one
// in-progress buffer per (Message ID, Request ID) so concurrent transfers do not
// collide (PRS_SOMEIP_00721 / 00731). Memory is bounded three ways — per-transfer size
// (max_message), number of concurrent transfers (max_concurrent), and transfer
// lifetime (timeout via mainFunction) — so neither a large nor an abandoned nor a
// flooding sender can grow it without bound.
class Reassembler {
public:
    enum class Status { kInProgress, kComplete, kError };

    struct Result {
        Status                    status = Status::kError;
        MessageHeader             header{};   // valid when kComplete (TP-flag cleared)
        std::vector<std::uint8_t> payload;    // valid when kComplete
    };

    Reassembler(std::size_t max_message, std::size_t max_concurrent,
                std::chrono::milliseconds timeout);

    // Feed one received on-wire SOME/IP-TP segment frame. Returns kComplete with the
    // reassembled message on the final, gap-free segment; kInProgress while more are
    // expected; kError on a malformed or inconsistent segment (its transfer is then
    // dropped). Unlike the Segmenter, feed() classifies UNTRUSTED wire data, so it
    // never throws — every reject is a kError, including duplicate offsets that
    // disagree on length or the More-Segments flag, a second inconsistent last
    // segment, and data reaching past the declared total.
    Result feed(const std::uint8_t* segment, std::size_t len);

    // Advance reception timers (the AUTOSAR main-function analog, as in tc8::nm),
    // abandoning — and reporting via onTimeout — every transfer whose age reaches the
    // configured timeout. Returns the number abandoned.
    std::size_t mainFunction(std::chrono::milliseconds elapsed);

    // Number of in-progress transfers held (diagnostics / backpressure).
    std::size_t pending() const { return pending_.size(); }

    std::function<void(const MessageHeader&)> onTimeout;  // incomplete transfer dropped

private:
    struct Segment {
        std::size_t len = 0;
        bool        more = false;
    };
    struct Pending {
        MessageHeader                  header;
        std::vector<std::uint8_t>      buf;
        std::map<std::size_t, Segment> segs;  // offset -> {length, more}; ordered for the walk
        bool                           last_seen = false;
        std::size_t                    total = 0;
        std::chrono::milliseconds      age{0};
    };

    std::size_t                      max_message_;
    std::size_t                      max_concurrent_;
    std::chrono::milliseconds        timeout_;
    std::map<std::uint64_t, Pending> pending_;  // key = message_id << 32 | request_id
};

}  // namespace tc8::someiptp
