#pragma once

#include <cstddef>
#include <cstdint>

// Shared big-endian field-read primitive for the wire-layout SSOTs.
//
// A `*_wire.def` declares every fixed-offset field as a row carrying an
// (off, size, shift, mask) quadruple. The authoritative C++ decoder
// expands those rows and the matching tools/gen_*_wire.py expands the same
// rows into a Python site mirror; both route the actual byte extraction
// through the one primitive below, so a row's four numbers are the only
// place the layout is written. Used by:
//   * someip_sd_wire.def  (SOME/IP-SD, see docs/tech-debt.md TD-01)
//   * dhcpv4_wire.def     (DHCPv4 BOOTP fixed header, TD-02)
// Each Python mirror's `_read` helper is the exact arithmetic twin of this
// function.
namespace tc8::wire {

// Read `size` bytes (1..4) big-endian starting at p, right-shift by `shift`,
// then mask with `mask`. The shift/mask pair expresses sub-byte bit slices
// declaratively (e.g. the SD NumberOfOpt1/2 nibbles and the
// Reserved(12b)|Counter(4b) split) so the .def, not hand-written shifting in
// each decoder, owns the layout.
inline std::uint32_t readBe(const std::uint8_t *p, std::size_t size, unsigned shift,
                            std::uint32_t mask) {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < size; ++i) {
        value = (value << 8) | p[i];
    }
    return (value >> shift) & mask;
}

}  // namespace tc8::wire
