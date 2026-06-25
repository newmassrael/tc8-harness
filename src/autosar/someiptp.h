#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <vector>

namespace tc8::someiptp {

// AUTOSAR SOME/IP base header fields (PRS_SOMEIP §4.1.2), carried big-endian on the
// wire. Every value is caller-supplied transported identity — Service / Method /
// Client / Session ids are OEM values passed per message, never baked into the
// engine. The engine copies them faithfully onto every segment (PRS_SOMEIP_00731)
// and hands them back on reassembly. Length is derived (not stored): the wire Length
// is computed per segment, and a reassembled message's length is its payload size.
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

// TP-Flag bit OR'd into the Message Type of every segment (PRS_SOMEIP_00722).
inline constexpr std::uint8_t kMessageTypeTpFlag = 0x20;

// The Offset field holds the upper 28 bits of a byte offset, so offsets and all
// non-last segment lengths are multiples of 16 (PRS_SOMEIP_00724 / 00729).
inline constexpr std::size_t kOffsetGranularity = 16;

// Recommended maximum segment payload (PRS_SOMEIP_00730).
inline constexpr std::size_t kRecommendedMaxSegment = 1392;

// Splits a SOME/IP message payload into SOME/IP-TP segments (PRS_SOMEIP §4.2.1.4).
// Stateless wire framing only; the owning module transmits each returned buffer.
class Segmenter {
public:
    // max_segment_payload = payload bytes per non-last segment. Must be a non-zero
    // multiple of kOffsetGranularity (PRS_SOMEIP_00724 / 00729); throws
    // std::invalid_argument otherwise.
    explicit Segmenter(std::size_t max_segment_payload);

    // Build the on-wire SOME/IP-TP segments for `payload`: each frame is the 16-byte
    // SOME/IP header + 4-byte TP header + segment bytes, with the Length, Message-Type
    // TP-flag, Offset and More-Segments flag set per the spec and the remaining header
    // fields copied from `hdr`. A payload that fits in one segment yields a single
    // segment with More-Segments = 0. Throws std::invalid_argument if payload is null
    // while len != 0.
    std::vector<std::vector<std::uint8_t>> segment(const MessageHeader& hdr,
                                                   const std::uint8_t* payload,
                                                   std::size_t len) const;

    std::size_t maxSegmentPayload() const { return max_segment_payload_; }

private:
    std::size_t max_segment_payload_;
};

// Reassembles received SOME/IP-TP segments back into original messages. Holds one
// in-progress buffer per (Message ID, Request ID) so concurrent transfers do not
// collide (PRS_SOMEIP_00721 / 00731). Time-driven via tick() so an incomplete
// transfer cannot leak indefinitely (the spec's SOME/IP-TP reception timeout).
class Reassembler {
public:
    enum class Status { kInProgress, kComplete, kError };

    struct Result {
        Status                    status = Status::kError;
        MessageHeader             header{};   // valid when kComplete (TP-flag cleared)
        std::vector<std::uint8_t> payload;    // valid when kComplete
    };

    // max_message bounds a reassembled payload — a transfer that would exceed it is
    // rejected (kError) rather than growing without bound. timeout bounds how long an
    // incomplete transfer is held before tick() abandons it.
    Reassembler(std::size_t max_message, std::chrono::milliseconds timeout);

    // Feed one received on-wire SOME/IP-TP segment frame. Returns kComplete with the
    // reassembled message on the final, gap-free segment; kInProgress while more are
    // expected; kError on a malformed or inconsistent segment (its transfer is
    // dropped). A malformed overlap does not complete and is reclaimed by timeout.
    Result feed(const std::uint8_t* segment, std::size_t len);

    // Advance reception timers; abandons (reporting via onTimeout) every transfer
    // whose age reaches the configured timeout. Returns the number abandoned.
    std::size_t tick(std::chrono::milliseconds elapsed);

    // Number of in-progress transfers (test / observability).
    std::size_t pending() const { return pending_.size(); }

    std::function<void(const MessageHeader&)> onTimeout;  // incomplete transfer dropped

private:
    struct Pending {
        MessageHeader                      header;
        std::vector<std::uint8_t>          buf;
        std::map<std::size_t, std::size_t> segs;  // offset -> length (coverage)
        bool                               last_seen = false;
        std::size_t                        total = 0;
        std::chrono::milliseconds          age{0};
    };

    std::size_t                        max_message_;
    std::chrono::milliseconds          timeout_;
    std::map<std::uint64_t, Pending>   pending_;  // key = message_id << 32 | request_id
};

}  // namespace tc8::someiptp
