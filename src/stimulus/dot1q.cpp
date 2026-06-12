#include "stimulus/dot1q.h"

#include <cstddef>
#include <cstdio>
#include <cstdlib>

namespace tc8::stimulus {

std::vector<std::uint8_t> withDot1QTag(const std::vector<std::uint8_t> &untagged,
                                       std::uint8_t pcp, bool dei, std::uint16_t vid,
                                       std::uint16_t tpid) {
    // Precondition: `untagged` is a complete Ethernet-II frame (>= 14 B:
    // dst + src + EtherType). A shorter buffer is a caller bug — there is
    // no MAC pair to splice the tag behind — so fail fast and loud rather
    // than fabricate a malformed frame or silently no-op. NDEBUG strips
    // assert() in the Release build, so this is an always-active guard in
    // the house std::abort() backstop style (see CaseRegistry::add).
    constexpr std::size_t kEthHeaderLen = 14U;
    if (untagged.size() < kEthHeaderLen) {
        std::fprintf(stderr,
                     "withDot1QTag: frame too short to tag (%zu B < 14 B"
                     " Ethernet header). Caller must pass a complete frame.\n",
                     untagged.size());
        std::abort();
    }

    // Tag Control Information: PCP(3) | DEI(1) | VID(12), per the shared
    // wire constants so the encode layout cannot drift from the decode.
    const std::uint16_t tci = static_cast<std::uint16_t>(
        ((static_cast<unsigned>(pcp) & 0x7U) << ::tc8::kDot1QPcpShift) |
        ((dei ? 1U : 0U) << ::tc8::kDot1QDeiShift) |
        (static_cast<unsigned>(vid) & ::tc8::kDot1QVidMask));

    std::vector<std::uint8_t> tagged;
    tagged.reserve(untagged.size() + 4U);

    // 12 B destination + source MAC, verbatim.
    tagged.insert(tagged.end(), untagged.begin(), untagged.begin() + 12);

    // 4 B tag: TPID then TCI, big-endian on the wire.
    tagged.push_back(static_cast<std::uint8_t>(tpid >> 8));
    tagged.push_back(static_cast<std::uint8_t>(tpid & 0xFFU));
    tagged.push_back(static_cast<std::uint8_t>(tci >> 8));
    tagged.push_back(static_cast<std::uint8_t>(tci & 0xFFU));

    // Original EtherType + payload — the EtherType is now the tag's
    // encapsulated type, exactly where 802.1Q places it.
    tagged.insert(tagged.end(), untagged.begin() + 12, untagged.end());
    return tagged;
}

}  // namespace tc8::stimulus
