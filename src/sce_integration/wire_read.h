#pragma once

#include <cstddef>
#include <cstdint>

// Shared big-endian field-read primitive for the wire-layout SSOTs.
//
// A `*_wire.def` declares every fixed-offset field as a row carrying its
// offset and width (SOME/IP-SD additionally carries a shift/mask for its
// sub-byte slices). The authoritative C++ decoder expands those rows and the
// matching tools/gen_*_wire.py expands the same rows into a Python site
// mirror; both route the actual byte extraction through the one primitive
// below, so a row's offset/width is the only place the layout is written.
// Used by:
//   * someip_sd_wire.def  (SOME/IP-SD, see docs/tech-debt.md TD-01)
//   * dhcpv4_wire.def     (DHCPv4 BOOTP fixed header, TD-02)
// Each Python mirror's `_read(buf, off, size)` helper is the exact arithmetic
// twin of this function.
namespace tc8::wire {

// Read `size` bytes (1..4) big-endian starting at p — the minimal shared
// atom. A consumer that needs a sub-byte slice (the SOME/IP-SD NumberOfOpt1/2
// nibbles and the Reserved(12b)|Counter(4b) split) applies `(value >> shift) &
// mask` at its own expansion site: that bit-slicing is a layout concern of the
// SD .def, not of this primitive, so an offset-aligned consumer (DHCPv4) is
// not taxed with it.
inline std::uint32_t readBe(const std::uint8_t *p, std::size_t size) {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < size; ++i) {
        value = (value << 8) | p[i];
    }
    return value;
}

}  // namespace tc8::wire
