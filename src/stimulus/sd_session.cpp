#include "stimulus/sd_session.h"

#include <algorithm>
#include <map>
#include <mutex>
#include <utility>
#include <vector>

#include "tc8/someip/protocol.h"           // kSdServiceId / kSdMethodId (SD Message ID SSOT)
#include "tc8/someip/sd_wire_constants.h"  // sd_flags::kReboot

namespace tc8::stimulus {

namespace {

// Byte offsets inside the UDP payload: the SOME/IP header's Session ID (the low half of
// the Request ID) and the SD flags byte that follows the 16-byte header.
constexpr std::size_t kSessionOffset = 10;
constexpr std::size_t kSdFlagsOffset = 16;

// A bound on the Sessions handed out and not yet seen on the wire. A draw that is never
// sent (its send failed, or a consumer drew and changed its mind) would otherwise stay
// here for the rest of the case; the oldest is dropped first, and a draw that old is not
// one a send is about to report.
constexpr std::size_t kMaxOutstandingDraws = 64;

struct Stream {
    std::uint16_t next = kSdSessionFirst;
    bool reboot = true;
    std::vector<std::uint16_t> outstanding;  // handed out by nextSdSession, not yet sent
};

using StreamKey = std::pair<std::uint32_t, std::uint32_t>;  // (src, dst), network order

std::mutex g_mutex;
std::map<StreamKey, Stream> g_streams;

// Move the stream past `sent`: the next Session follows it, and the wrap 0xFFFF -> 0x0001
// clears the Reboot flag (SD §4.2.1).
void advancePast(Stream &s, std::uint16_t sent) {
    if (sent == 0xFFFF) {
        s.next = kSdSessionFirst;
        s.reboot = false;
    } else {
        s.next = static_cast<std::uint16_t>(sent + 1U);
    }
}

}  // namespace

SdSession nextSdSession(std::uint32_t src_ipv4_be, std::uint32_t dst_ipv4_be) {
    const std::lock_guard<std::mutex> lock(g_mutex);
    Stream &s = g_streams[{src_ipv4_be, dst_ipv4_be}];
    const SdSession out{s.next, s.reboot};
    advancePast(s, out.session_id);
    if (s.outstanding.size() >= kMaxOutstandingDraws) {
        s.outstanding.erase(s.outstanding.begin());
    }
    s.outstanding.push_back(out.session_id);
    return out;
}

std::uint8_t sdFlagsWithReboot(std::uint8_t flags, bool reboot) {
    constexpr std::uint8_t kReboot = ::tc8::sd_flags::kReboot;
    return reboot ? static_cast<std::uint8_t>(flags | kReboot)
                  : static_cast<std::uint8_t>(flags & static_cast<std::uint8_t>(~kReboot));
}

void noteSdDatagramSent(std::uint32_t src_ipv4_be, std::uint32_t dst_ipv4_be,
                        const std::uint8_t *datagram, std::size_t size) {
    if (datagram == nullptr || size <= kSdFlagsOffset) {
        return;
    }
    const auto be16 = [datagram](std::size_t at) {
        return static_cast<std::uint16_t>((datagram[at] << 8) | datagram[at + 1]);
    };
    if (be16(0) != someip::kSdServiceId || be16(2) != someip::kSdMethodId) {
        return;
    }
    const std::uint16_t session = be16(kSessionOffset);
    const bool reboot = (datagram[kSdFlagsOffset] & ::tc8::sd_flags::kReboot) != 0;

    const std::lock_guard<std::mutex> lock(g_mutex);
    Stream &s = g_streams[{src_ipv4_be, dst_ipv4_be}];
    const auto drawn = std::find(s.outstanding.begin(), s.outstanding.end(), session);
    if (drawn != s.outstanding.end()) {
        // A Session this stream handed out: the counter moved past it when it was drawn,
        // and a later draw may already have gone out, so it must not be moved back here.
        s.outstanding.erase(drawn);
        return;
    }
    // A Session the sender chose. The stream continues from it, with its Reboot flag.
    // Draws not yet seen on the wire are forgotten: they belong to the numbering this
    // choice replaced, and one left behind (a draw whose send failed) would make a later
    // choice of the same value read as that draw and not move the stream.
    s.reboot = reboot;
    advancePast(s, session);
    s.outstanding.clear();
}

void resetSdSessions() {
    const std::lock_guard<std::mutex> lock(g_mutex);
    g_streams.clear();
}

}  // namespace tc8::stimulus
