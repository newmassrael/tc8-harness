#pragma once

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string_view>

namespace tc8 {

// Ceiling for an expected payload supplied via `--expect [<group>.]payload=HH:..`
// or a case's applyExpectedDefaults. Echo payloads are small (primitives, short
// structs and arrays, a short ICMP data field); a token that exceeds this makes
// the parser reject it (fail-loud) rather than silently truncate.
inline constexpr std::size_t kMaxExpectedPayload = 256;

// The expected payload a case compares a captured payload against — a
// Method-Response echo (SOME/IP ETS) or an Echo Reply data field (ICMPv4). A
// data-only base of each expectation DTO that carries one, so the storage, its
// capacity, the accessor and the override rule below are declared once rather
// than per protocol. Inherited, not composed, for the same reason the DTOs
// themselves are inherited by their Named Contexts: SCE's expression rewriter
// takes `expected.payload_view()` but not `expected.payload.view()`.
//
// `payload_len` is the count of valid leading bytes; 0 means UNSET. A case
// installs its conformant value through setExpectedPayload from its
// applyExpectedDefaults hook, and the negative harness replaces it with a
// deliberately wrong `payload=` token (see keepCaseDefaultPayloadUnlessSet).
struct ExpectedPayload {
    std::array<std::uint8_t, kMaxExpectedPayload> payload{};
    std::uint32_t payload_len = 0;

    std::string_view payload_view() const {
        return std::string_view(reinterpret_cast<const char *>(payload.data()), payload_len);
    }
};

// Set a case-local expected payload default — the conformant bytes a
// test-intrinsic assertion compares against. Called from a case's
// `applyExpectedDefaults` hook. The size is a compile-tree authoring invariant,
// so an over-capacity value fails loud (assert) rather than silently
// truncating — matching the CLI parser, which rejects an over-capacity token.
inline void setExpectedPayload(ExpectedPayload &e, const std::uint8_t *bytes, std::size_t len) {
    assert(len <= e.payload.size() && "expected payload exceeds kMaxExpectedPayload");
    e.payload.fill(0);
    e.payload_len = 0;
    for (std::size_t i = 0; i < len && e.payload_len < e.payload.size(); ++i) {
        e.payload[e.payload_len++] = bytes[i];
    }
}

inline void setExpectedPayload(ExpectedPayload &e, std::initializer_list<std::uint8_t> bytes) {
    setExpectedPayload(e, bytes.begin(), bytes.size());
}

// A payload held as a byte string, e.g. a spec text literal the stimulus sends.
inline void setExpectedPayload(ExpectedPayload &e, std::string_view bytes) {
    setExpectedPayload(e, reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size());
}

// The payload is the one expectation that overrides only when set. Each
// Named Context's applyTestConfig copies its DTO from `--expect` wholesale,
// AFTER the case's applyExpectedDefaults ran; an unconditional copy would wipe
// the case default with the empty CLI default on every positive run. So the
// CLI value wins only when a `payload=` token was actually given
// (payload_len > 0), and the case default survives otherwise. A genuinely
// empty echo is asserted via `captured.payload_len == 0` in SCXML (cf.
// ETS_003), not through this path.
inline void keepCaseDefaultPayloadUnlessSet(ExpectedPayload &effective,
                                            const ExpectedPayload &case_default) {
    if (effective.payload_len == 0) {
        effective = case_default;
    }
}

}  // namespace tc8
