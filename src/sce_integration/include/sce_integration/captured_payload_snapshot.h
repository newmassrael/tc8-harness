#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string_view>

namespace tc8 {

// Shared L4 payload-snapshot surface for every SCE Named Context that
// observes an application-layer payload on the wire (SOME/IP, UDP, TCP,
// ICMPv4). Owns the byte storage, the captured-length companion, the
// bounded-copy fill path, and the comparison helpers — all defined
// ONCE so the ceiling value, the storage idiom, the truncation-guard
// semantics, and the SCXML-facing verbs cannot drift across protocols.
//
// `kMaxPayloadSnapshot` is 64 KiB. A payload is not bounded by one Ethernet
// frame: a SOME/IP message reassembled from a TCP stream, or one carried in
// a fragmented IPv4 datagram, is handed to a case whole, and a case may echo
// a 2048-byte array. 64 KiB holds any payload one IPv4 datagram can carry
// and a SOME/IP-over-TCP message up to that size; it is a capture budget,
// so a longer payload is cut, never silently. Overflow is never silent: `payload_snapshot_len`
// records how many bytes were actually captured (min(wire_len, cap)),
// and every comparison helper rejects an assertion that reaches past
// the captured window — so a truncated capture fails the guard instead
// of masquerading as a match.
//
// Inherited (not composed as a nested member) so SCXML conditions keep
// the single-dot `cpp:captured.payload_bytes_eq(...)` /
// `captured.payload_snapshot[N]` form that SCE's expression rewriter
// requires — it rewrites `captured.X` into `this->captured_->X` but not
// `captured.X.Y` (see docs/scxml_guard_expressions.md). Through a derived
// pointer, inherited member and method access stays single-dot, so the
// rewrite applies uniformly.
//
// The type has only data + non-virtual methods, so a Captured struct
// that derives from it remains an aggregate under C++17 (a public base
// with no user-declared constructors is permitted), keeping the
// existing `SomeIpCaptured c{};` value-initialisation and POD copy
// semantics intact.
struct CapturedPayloadSnapshot {
    static constexpr std::size_t kMaxPayloadSnapshot = 64U * 1024U;
    std::array<std::uint8_t, kMaxPayloadSnapshot> payload_snapshot{};
    std::uint32_t payload_snapshot_len = 0;

    // Bounded copy from a non-owning wire pointer (valid only during the
    // dispatch call). Every byte past the new length is zero afterwards, so
    // a re-used Captured never leaks a prior frame's bytes past it. Only the
    // bytes the previous frame left past the new length are cleared (the rest
    // are zero already), so a frame costs its own length, not the capacity.
    // The single copy path the four fill functions share instead of each
    // re-implementing the reset + min() + copy + length assignment.
    void fillPayloadSnapshot(const std::uint8_t *data, std::uint32_t len) {
        const std::size_t previous_len = payload_snapshot_len;
        std::size_t copy_len = 0;
        if (data != nullptr && len != 0) {
            copy_len = std::min<std::size_t>(static_cast<std::size_t>(len), payload_snapshot.size());
            std::memcpy(payload_snapshot.data(), data, copy_len);
        }
        if (previous_len > copy_len) {
            std::memset(payload_snapshot.data() + copy_len, 0, previous_len - copy_len);
        }
        payload_snapshot_len = static_cast<std::uint32_t>(copy_len);
    }

    // Pin the leading `expected.size()` bytes of the captured payload
    // against a wire-literal pattern. Returns true iff every byte in the
    // initializer list matches AND the snapshot actually captured at
    // least that many bytes, so a partial-frame truncation — or a
    // payload that overran `kMaxPayloadSnapshot` — never sneaks past as
    // a match. Verifies a PREFIX, not the whole payload: pair with
    // `captured.payload_len == N` when full-length verification is also
    // required. Used by SOME/IP ETS Method-Response echo conds and any
    // L7-over-TCP case via `cpp:captured.payload_bytes_eq({0x02, ...})`.
    bool payload_bytes_eq(std::initializer_list<std::uint8_t> expected) const {
        if (expected.size() > payload_snapshot.size()) {
            return false;
        }
        if (expected.size() > payload_snapshot_len) {
            return false;
        }
        std::size_t i = 0;
        for (auto b : expected) {
            if (payload_snapshot[i++] != b) {
                return false;
            }
        }
        return true;
    }

    // Full-length exact-match against a reference byte view: the
    // captured payload must be exactly `reference.size()` bytes and
    // equal byte-for-byte. Distinct from `payload_bytes_eq`, which only
    // pins a prefix. The ICMPv4 Echo-Reply check asserts the DUT echoed
    // the tester's payload verbatim, with no trailing extra.
    bool payload_equals(std::string_view reference) const {
        if (payload_snapshot_len != reference.size()) {
            return false;
        }
        if (reference.size() > payload_snapshot.size()) {
            return false;
        }
        return std::memcmp(payload_snapshot.data(), reference.data(),
                           reference.size()) == 0;
    }

    // Assert the captured payload is exactly `len` bytes and each byte
    // equals `i & 0xFF` — the canonical index ramp the harness fills via
    // `byte[i] = i & 0xFF` (e.g. cases/ipv4_header_05.h::makeHeader05
    // Payload). A DUT that echoed the right length but garbage data
    // fails. Protocol-neutral, so any large-payload echo case can reuse
    // it. The IPv4 large-datagram Echo-Data case is the first consumer.
    bool payload_matches_index_pattern(std::uint32_t len) const {
        if (payload_snapshot_len != len) {
            return false;
        }
        if (len > payload_snapshot.size()) {
            return false;
        }
        for (std::uint32_t i = 0; i < len; ++i) {
            if (payload_snapshot[i] != static_cast<std::uint8_t>(i & 0xFFU)) {
                return false;
            }
        }
        return true;
    }
};

}  // namespace tc8
