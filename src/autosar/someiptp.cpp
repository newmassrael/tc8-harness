#include "autosar/someiptp.h"

#include <algorithm>
#include <stdexcept>

namespace tc8::someiptp {
namespace {

void put32be(std::vector<std::uint8_t>& b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 24));
    b.push_back(static_cast<std::uint8_t>(v >> 16));
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}

std::uint32_t get32be(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

std::uint64_t transferKey(std::uint32_t message_id, std::uint32_t request_id) {
    return (static_cast<std::uint64_t>(message_id) << 32) | request_id;
}

}  // namespace

bool parseTpHeader(const std::uint8_t* tp_header, std::size_t len, TpSegmentHeader& out) {
    if (tp_header == nullptr || len < kTpHeaderLen) {
        return false;
    }
    const std::uint32_t tp = get32be(tp_header);
    // The 16-byte-granular offset occupies the upper 28 bits, so masking off the low 4
    // bits (kOffsetGranularity-1) drops the Reserved (3) + More-Segments (1) field that
    // shares them (PRS_SOMEIP_00724 / 00726). More-Segments is bit 0.
    out.offset = tp & ~static_cast<std::uint32_t>(kOffsetGranularity - 1);
    out.more_segments = (tp & 1u) != 0;
    return true;
}

Segmenter::Segmenter(std::size_t max_segment_payload) : max_segment_payload_(max_segment_payload) {
    if (max_segment_payload_ == 0 || max_segment_payload_ % kOffsetGranularity != 0) {
        throw std::invalid_argument(
            "tc8::someiptp::Segmenter: max_segment_payload must be a non-zero multiple of 16");
    }
    // A segment's wire Length (kLengthCoveredHeaderBytes + TP header + payload) must fit
    // its uint32 field.
    if (max_segment_payload_ > 0xFFFFFFFFull - (kLengthCoveredHeaderBytes + kTpHeaderLen)) {
        throw std::invalid_argument(
            "tc8::someiptp::Segmenter: max_segment_payload overflows the SOME/IP Length field");
    }
}

std::vector<std::vector<std::uint8_t>> Segmenter::segment(const MessageHeader& hdr,
                                                          const std::uint8_t* payload,
                                                          std::size_t len,
                                                          std::uint8_t reserved) const {
    if (payload == nullptr && len != 0) {
        throw std::invalid_argument("tc8::someiptp::Segmenter::segment: null payload with len != 0");
    }
    // The last segment starts at the largest multiple of max_segment_payload_ below len;
    // it must be addressable by the 28-bit Offset field (PRS_SOMEIP_00724).
    if (len != 0) {
        const std::size_t last_offset = ((len - 1) / max_segment_payload_) * max_segment_payload_;
        if (last_offset > kMaxByteOffset) {
            throw std::length_error(
                "tc8::someiptp::Segmenter::segment: payload too large for the SOME/IP-TP Offset field");
        }
    }

    std::vector<std::vector<std::uint8_t>> out;
    std::size_t offset = 0;
    do {
        const std::size_t seg_len = std::min(max_segment_payload_, len - offset);
        const bool        more = (offset + seg_len) < len;

        std::vector<std::uint8_t> frame;
        frame.reserve(kSegmentHeaderLen + seg_len);
        // SOME/IP header: the Length field covers Request ID onward —
        // kLengthCoveredHeaderBytes (Request ID .. Return Code) + the 4-byte TP header +
        // this segment (PRS_SOMEIP_00728).
        put32be(frame, hdr.message_id);
        put32be(frame, static_cast<std::uint32_t>(kLengthCoveredHeaderBytes + kTpHeaderLen + seg_len));
        put32be(frame, hdr.request_id);
        frame.push_back(hdr.protocol_version);
        frame.push_back(hdr.interface_version);
        frame.push_back(static_cast<std::uint8_t>(hdr.message_type | kMessageTypeTpFlag));
        frame.push_back(hdr.return_code);
        // TP header (PRS_SOMEIP_00723 / Table 4.8): the byte offset is 16-aligned, so its
        // low 4 bits are zero and it already occupies the upper-28-bit Offset field
        // directly; bits 3..1 are Reserved (0 on the conformant wire; `reserved` lets a
        // negative test set them); bit 0 is the More-Segments flag.
        put32be(frame, static_cast<std::uint32_t>(offset) |
                           (static_cast<std::uint32_t>(reserved & 0x7u) << 1) |
                           (more ? 1u : 0u));
        if (seg_len != 0) {
            frame.insert(frame.end(), payload + offset, payload + offset + seg_len);
        }

        out.push_back(std::move(frame));
        offset += seg_len;
    } while (offset < len);
    return out;
}

Reassembler::Reassembler(std::size_t max_message, std::size_t max_concurrent,
                         std::chrono::milliseconds timeout)
    : max_message_(max_message), max_concurrent_(max_concurrent), timeout_(timeout) {}

Reassembler::Result Reassembler::feed(const std::uint8_t* segment, std::size_t len) {
    Result res;  // defaults to kError
    if (segment == nullptr || len < kSegmentHeaderLen) {
        return res;
    }

    MessageHeader       hdr;
    hdr.message_id = get32be(segment);
    const std::uint32_t length = get32be(segment + 4);
    hdr.request_id = get32be(segment + 8);
    hdr.protocol_version = segment[12];
    hdr.interface_version = segment[13];
    const std::uint8_t  raw_type = segment[14];
    hdr.return_code = segment[15];

    // Must carry the TP-Flag (PRS_SOMEIP_00722).
    if ((raw_type & kMessageTypeTpFlag) == 0) {
        return res;
    }
    hdr.message_type = static_cast<std::uint8_t>(raw_type & ~kMessageTypeTpFlag);

    // Length covers Request ID onward (8) + TP header (4) + segment (PRS_SOMEIP_00728).
    if (length < kLengthCoveredHeaderBytes + kTpHeaderLen) {
        return res;
    }
    const std::size_t seg_len = length - kLengthCoveredHeaderBytes - kTpHeaderLen;
    if (kSegmentHeaderLen + seg_len > len) {
        return res;  // frame truncated relative to its Length field
    }

    // Decode Offset / More-Segments via the shared parser (the len guard above
    // guarantees the 4-byte TP header is present).
    TpSegmentHeader tph;
    parseTpHeader(segment + kSomeipHeaderLen, len - kSomeipHeaderLen, tph);
    const std::size_t offset = tph.offset;
    const bool        more = tph.more_segments;

    // A non-last segment must carry a non-zero, 16-aligned length (PRS_SOMEIP_00729); a
    // zero-length non-last segment advances nothing and would stall reassembly.
    if (more && (seg_len == 0 || seg_len % kOffsetGranularity != 0)) {
        return res;
    }

    const std::uint64_t key = transferKey(hdr.message_id, hdr.request_id);

    if (offset + seg_len > max_message_) {
        pending_.erase(key);  // bound per-transfer memory; drop any transfer for this id
        return res;
    }

    auto it = pending_.find(key);
    if (it == pending_.end()) {
        if (pending_.size() >= max_concurrent_) {
            return res;  // bound the number of concurrent transfers
        }
        Pending p;
        p.header = hdr;
        it = pending_.emplace(key, std::move(p)).first;
    } else {
        // All segments share the original's header beyond the routing key
        // (PRS_SOMEIP_00731); a mismatch is a malformed transfer.
        const MessageHeader& h = it->second.header;
        if (h.protocol_version != hdr.protocol_version ||
            h.interface_version != hdr.interface_version || h.message_type != hdr.message_type ||
            h.return_code != hdr.return_code) {
            pending_.erase(it);
            return res;
        }
    }
    Pending& p = it->second;

    // Once the final extent is known, reject anything inconsistent with it: data past
    // the total, or a second "last" segment declaring a different total.
    if (p.last_seen) {
        if (offset + seg_len > p.total || (!more && offset + seg_len != p.total)) {
            pending_.erase(it);
            return res;
        }
    }

    // Place / validate this offset. A repeat must agree on BOTH length and the
    // More-Segments flag — a flipped flag at a known offset is malformed, not a dup.
    const auto seg_it = p.segs.find(offset);
    if (seg_it != p.segs.end()) {
        if (seg_it->second.len != seg_len || seg_it->second.more != more) {
            pending_.erase(it);
            return res;
        }
        // Exact duplicate (retransmission): already placed.
    } else {
        p.segs[offset] = Segment{seg_len, more};
        if (p.buf.size() < offset + seg_len) {
            p.buf.resize(offset + seg_len, 0x00);
        }
        if (seg_len != 0) {
            std::copy(segment + kSegmentHeaderLen, segment + kSegmentHeaderLen + seg_len,
                      p.buf.begin() + static_cast<std::ptrdiff_t>(offset));
        }
    }

    if (!more) {
        // This is the last segment — it fixes the total. Any already-recorded segment
        // reaching past that total makes the transfer inconsistent.
        const std::size_t total = offset + seg_len;
        for (const auto& off_seg : p.segs) {
            if (off_seg.first + off_seg.second.len > total) {
                pending_.erase(it);
                return res;
            }
        }
        p.last_seen = true;
        p.total = total;
    }

    p.age = std::chrono::milliseconds{0};

    if (p.last_seen) {
        // Complete once coverage is contiguous from 0 to total. Gaps (off > cursor) and
        // overlaps (off < cursor) both leave cursor != total, so neither completes here.
        std::size_t cursor = 0;
        bool        contiguous = true;
        for (const auto& off_seg : p.segs) {
            if (off_seg.first != cursor) {
                contiguous = false;
                break;
            }
            cursor += off_seg.second.len;
        }
        if (contiguous && cursor == p.total) {
            res.status = Status::kComplete;
            res.header = p.header;
            p.buf.resize(p.total);
            res.payload = std::move(p.buf);
            pending_.erase(it);
            return res;
        }
    }

    res.status = Status::kInProgress;
    return res;
}

std::size_t Reassembler::mainFunction(std::chrono::milliseconds elapsed) {
    std::vector<std::uint64_t> expired;
    for (auto& key_pending : pending_) {
        key_pending.second.age += elapsed;
        if (key_pending.second.age >= timeout_) {
            expired.push_back(key_pending.first);
        }
    }
    for (const std::uint64_t key : expired) {
        if (onTimeout) {
            onTimeout(pending_[key].header);
        }
        pending_.erase(key);
    }
    return expired.size();
}

}  // namespace tc8::someiptp
