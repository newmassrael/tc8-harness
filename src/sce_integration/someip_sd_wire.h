#pragma once

#include <cstddef>
#include <cstdint>

// Shared support for the SOME/IP-SD wire layout SSOT in someip_sd_wire.def.
//
// The .def declares every fixed-offset SD field as a row carrying an
// (off, size, shift, mask) quadruple. someip_captured.h expands those rows
// (the authoritative C++ decoder) and tools/gen_someip_sd_wire.py expands
// the same rows into the Python site mirror. Both route the actual byte
// extraction through the one primitive below, so a row's four numbers are
// the only place the layout is written. See docs/tech-debt.md TD-01.
namespace tc8::sd_wire {

// Read `size` bytes (1..4) big-endian starting at p, right-shift by `shift`,
// then mask with `mask`. The shift/mask pair expresses the sub-byte bit
// slices declaratively (the NumberOfOpt1/2 nibbles and the
// Reserved(12b)|Counter(4b) split) so the .def, not hand-written shifting in
// each decoder, owns the layout. The Python mirror's `_read` helper is the
// exact arithmetic twin of this function.
inline std::uint32_t readBe(const std::uint8_t *p, std::size_t size, unsigned shift,
                            std::uint32_t mask) {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < size; ++i) {
        value = (value << 8) | p[i];
    }
    return (value >> shift) & mask;
}

}  // namespace tc8::sd_wire
