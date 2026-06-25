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

Segmenter::Segmenter(std::size_t max_segment_payload) : max_segment_payload_(max_segment_payload) {
    if (max_segment_payload_ == 0 || max_segment_payload_ % kOffsetGranularity != 0) {
        throw std::invalid_argument(
            "tc8::someiptp::Segmenter: max_segment_payload must be a non-zero multiple of 16");
    }
}

std::vector<std::vector<std::uint8_t>> Segmenter::segment(const MessageHeader& hdr,
                                                          const std::uint8_t* payload,
                                                          std::size_t len) const {
    if (payload == nullptr && len != 0) {
        throw std::invalid_argument("tc8::someiptp::Segmenter::segment: null payload with len != 0");
    }
    std::vector<std::vector<std::uint8_t>> out;
    std::size_t offset = 0;
    do {
        const std::size_t seg_len = std::min(max_segment_payload_, len - offset);
        const bool        more = (offset + seg_len) < len;

        std::vector<std::uint8_t> frame;
        frame.reserve(kSegmentHeaderLen + seg_len);
        // SOME/IP header: the Length field covers Request ID onward — 8 bytes
        // (Request ID .. Return Code) + the 4-byte TP header + this segment
        // (PRS_SOMEIP_00728).
        put32be(frame, hdr.message_id);
        put32be(frame, static_cast<std::uint32_t>(8 + kTpHeaderLen + seg_len));
        put32be(frame, hdr.request_id);
        frame.push_back(hdr.protocol_version);
        frame.push_back(hdr.interface_version);
        frame.push_back(static_cast<std::uint8_t>(hdr.message_type | kMessageTypeTpFlag));
        frame.push_back(hdr.return_code);
        // TP header (PRS_SOMEIP_00723 / Table 4.8): the byte offset already has its
        // low 4 bits zero (segments are 16-aligned), so it occupies the Offset field
        // directly; Reserved bits stay 0; bit 0 is the More-Segments flag.
        put32be(frame, static_cast<std::uint32_t>(offset) | (more ? 1u : 0u));
        if (seg_len != 0) {
            frame.insert(frame.end(), payload + offset, payload + offset + seg_len);
        }

        out.push_back(std::move(frame));
        offset += seg_len;
    } while (offset < len);
    return out;
}

Reassembler::Reassembler(std::size_t max_message, std::chrono::milliseconds timeout)
    : max_message_(max_message), timeout_(timeout) {}

Reassembler::Result Reassembler::feed(const std::uint8_t* segment, std::size_t len) {
    Result res;
    if (segment == nullptr || len < kSegmentHeaderLen) {
        return res;  // kError
    }

    MessageHeader      hdr;
    hdr.message_id = get32be(segment);
    const std::uint32_t length = get32be(segment + 4);
    hdr.request_id = get32be(segment + 8);
    hdr.protocol_version = segment[12];
    hdr.interface_version = segment[13];
    const std::uint8_t raw_type = segment[14];
    hdr.return_code = segment[15];
    const std::uint32_t tp = get32be(segment + kSomeipHeaderLen);

    // Must carry the TP-Flag (PRS_SOMEIP_00722).
    if ((raw_type & kMessageTypeTpFlag) == 0) {
        return res;  // kError
    }
    hdr.message_type = static_cast<std::uint8_t>(raw_type & ~kMessageTypeTpFlag);

    // Length covers Request ID onward (8) + TP header (4) + segment (PRS_SOMEIP_00728).
    if (length < 8 + kTpHeaderLen) {
        return res;  // kError
    }
    const std::size_t seg_len = length - 8 - kTpHeaderLen;
    if (kSegmentHeaderLen + seg_len > len) {
        return res;  // kError — frame truncated relative to its Length field
    }

    // Offset field = upper 28 bits (low 4 bits / Reserved ignored, PRS_SOMEIP_00726).
    const std::size_t offset = tp & ~static_cast<std::uint32_t>(kOffsetGranularity - 1);
    const bool        more = (tp & 1u) != 0;

    // Non-last segments are 16-aligned in length (PRS_SOMEIP_00729).
    if (more && (seg_len % kOffsetGranularity) != 0) {
        return res;  // kError
    }

    const std::uint64_t key = transferKey(hdr.message_id, hdr.request_id);

    if (offset + seg_len > max_message_) {
        pending_.erase(key);  // bound memory; drop any in-progress transfer for this id
        return res;           // kError
    }

    auto it = pending_.find(key);
    if (it == pending_.end()) {
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
            return res;  // kError
        }
    }
    Pending& p = it->second;
    p.age = std::chrono::milliseconds{0};

    const auto seg_it = p.segs.find(offset);
    if (seg_it != p.segs.end()) {
        if (seg_it->second != seg_len) {
            pending_.erase(it);
            return res;  // kError — same offset, conflicting length
        }
        // Exact duplicate: already placed, ignore.
    } else {
        p.segs[offset] = seg_len;
        if (p.buf.size() < offset + seg_len) {
            p.buf.resize(offset + seg_len, 0x00);
        }
        if (seg_len != 0) {
            std::copy(segment + kSegmentHeaderLen, segment + kSegmentHeaderLen + seg_len,
                      p.buf.begin() + static_cast<std::ptrdiff_t>(offset));
        }
    }

    if (!more) {
        p.last_seen = true;
        p.total = offset + seg_len;
    }

    if (p.last_seen) {
        // Complete once coverage is contiguous from 0 to total (gaps and overlaps
        // both leave cursor != total, so neither completes here).
        std::size_t cursor = 0;
        bool        contiguous = true;
        for (const auto& off_len : p.segs) {
            if (off_len.first != cursor) {
                contiguous = false;
                break;
            }
            cursor += off_len.second;
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

std::size_t Reassembler::tick(std::chrono::milliseconds elapsed) {
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
