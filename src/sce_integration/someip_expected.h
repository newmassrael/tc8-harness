#pragma once

#include <array>
#include <cassert>
#include <cstdint>
#include <initializer_list>
#include <string_view>

#include "someip_expectations.h"
#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying DUT-identity values supplied by the
// CLI via `--expect`. Matching SCXML declaration:
//   <sce:context id="expected" cpp:type="tc8::SomeIpExpected"
//                cpp:include="sce_integration/someip_expected.h"/>
//
// Cases whose Test Procedure compares captured entry fields against a
// configured SERVICE-ID-1 identity (FORMAT_14..18) read these from their
// SCXML guards, e.g.
//
//   cond="cpp:captured.sd_entries[0].service_id == expected.service_id"
//
// Default 0 is never a valid DUT identity for the SOME/IP §5.1 suite,
// so a case that lands here with expectations unset will fall into its
// fail_* sink — the failure reason plus the CLI banner lets the operator
// notice the missing configuration without another layer of validation
// plumbing.
//
// Cases that don't read expected values (FORMAT_01..13) still declare
// this context in their SCXML so the SCE codegen emits a uniform two-arg
// state-machine constructor; `TestRunner<SM>` always constructs both
// captured and expected unconditionally.
// Every expected value is a `SomeIpExpectations` DTO field, INHERITED (not
// composed) so SCXML conditions keep the single-dot `cpp:expected.service_id`
// form SCE's expression rewriter requires — it rewrites `expected.X` into
// `this->expected_->X` but not `expected.X.Y`. This is the same data-only-base
// idiom the captured contexts use (cf. `captured_l4_ports.h`, where
// `SomeIpCaptured` reads inherited `src_port` single-dot). Declaring the fields
// ONCE in the base is the SSOT: a new `--expect` field is added to
// `SomeIpExpectations` alone and cannot drift between the DTO and this Named
// Context. This struct adds only the payload accessor.
struct SomeIpExpected : SomeIpExpectations {
    std::string_view payload_view() const {
        return std::string_view(reinterpret_cast<const char *>(payload.data()),
                                payload_len);
    }
};

// ADL hook called by `TestRunner<SM>` at construction for any case whose
// expected-context Named Context is `SomeIpExpected`. Copies the flat DTO
// fields supplied via CLI `--expect`. Adding a new Named Context type
// means adding a matching overload in its own header; missing overloads
// fail at compile time rather than silently skipping configuration.
inline void applyTestConfig(SomeIpExpected &e, const TestConfig &cfg) {
    // One memberwise copy of the shared base subobject pulls EVERY CLI
    // `--expect` scalar (identity, endpoints, SD/CAN timing thresholds) across
    // in a single assignment, so a field added to the `SomeIpExpectations` DTO
    // can never be silently forgotten here — the per-field copy this replaced
    // was exactly that drift hazard.
    SomeIpExpectations effective = cfg.someip;
    // payload is the lone override-only-when-set field: a case installs a
    // conformant default via setExpectedPayload (its applyExpectedDefaults
    // hook) and `--expect payload=` overrides it ONLY when explicitly given
    // (payload_len > 0). Preserve the case default when the CLI leaves it
    // unset — an unconditional copy would wipe it with the empty CLI default
    // on every positive run. `payload_len == 0` means *unset* (keep default),
    // so a genuinely empty echo is asserted via `captured.payload_len == 0` in
    // SCXML (cf. ETS_003), not through this path.
    if (effective.payload_len == 0) {
        effective.payload = e.payload;
        effective.payload_len = e.payload_len;
    }
    static_cast<SomeIpExpectations &>(e) = effective;
}

// Set a case-local expected L7 payload default — the conformant echo a
// test-intrinsic ETS assertion compares against. Called from a case's
// `applyExpectedDefaults` hook; `--expect payload=` overrides it for the
// negative. The size is a compile-tree authoring invariant, so an over-capacity
// literal fails loud (assert) rather than silently truncating — matching the
// CLI parser, which rejects an over-capacity `payload=` token.
inline void setExpectedPayload(SomeIpExpected &e, std::initializer_list<std::uint8_t> bytes) {
    assert(bytes.size() <= e.payload.size() && "expected payload exceeds kMaxExpectedPayload");
    e.payload.fill(0);
    e.payload_len = 0;
    for (auto b : bytes) {
        if (e.payload_len < e.payload.size()) {
            e.payload[e.payload_len++] = b;
        }
    }
}

}  // namespace tc8
