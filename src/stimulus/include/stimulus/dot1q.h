#pragma once

#include <cstdint>
#include <vector>

#include "tc8/protocol_frames/dot1q_tag.h"

namespace tc8::stimulus {

// Splice a single IEEE 802.1Q tag into a complete Ethernet-II frame.
//
// `untagged` is a full frame — 6 B destination MAC, 6 B source MAC, 2 B
// EtherType/Length, then payload. The returned copy inserts the 4-byte
// tag (TPID then TCI, big-endian) immediately after the 12-byte MAC
// pair, preserving the original EtherType as the tag's encapsulated
// type — exactly the layout `tc8::Dot1QTag` documents and the dissector
// reads back. The encode here and the decode in
// `tc8::dissect::PacketPipeline` share the wire constants in
// `tc8/protocol_frames/dot1q_tag.h`, and `dot1q_test` round-trips a
// built frame through libtins to pin the two sides together.
//
// Composes transparently with `sendRawEthernet`: that injector reads the
// EtherType at offset 12..13, which now holds 0x8100, so the kernel hint
// follows the tag without any caller change.
//
// `pcp` is masked to 3 bits and `vid` to 12 bits. Precondition:
// `untagged` MUST be a complete Ethernet-II frame (>= 14 bytes) — there
// is otherwise no MAC pair to splice the tag behind. A shorter buffer is
// a caller bug and aborts with a diagnostic (fail fast; NDEBUG would
// strip a bare assert in the Release build).
std::vector<std::uint8_t> withDot1QTag(const std::vector<std::uint8_t> &untagged,
                                       std::uint8_t pcp, bool dei, std::uint16_t vid,
                                       std::uint16_t tpid = ::tc8::kDot1QTpid);

}  // namespace tc8::stimulus
