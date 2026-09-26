#pragma once

#include "expected_payload.h"
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
// Context. The payload accessor `expected.payload_view()` and the case-default
// setter come from the shared ExpectedPayload base (expected_payload.h).
struct SomeIpExpected : SomeIpExpectations {
    // The service the tester is TALKING TO, copied from `SomeIpIdentity` rather
    // than from the expectations above. A direct member, not inherited, because
    // it is deliberately NOT part of the `--expect`-flippable DTO — and
    // single-dot `expected.dut_service_id` still satisfies SCE's rewriter.
    //
    // It exists for the guards that ask WHICH PEER rather than WHAT VALUE. A
    // two-phase case waits for the DUT's OfferService before provoking the frame
    // it grades; that wait is a question about the peer, so pinning it to the
    // expectation made the whole case unfaultable — flip the expectation to test
    // phase 2's guard and phase 1 stops recognising the offer, so the run ends in
    // a non-conclusion and the guard is never reached (SOMEIPSRV_RPC_18,
    // docs/tech-debt.md TD-55).
    std::uint16_t dut_service_id = 0;
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
    keepCaseDefaultPayloadUnlessSet(effective, e);
    static_cast<SomeIpExpectations &>(e) = effective;
    // Assigned after the base-slice above, which by construction leaves direct
    // members untouched. Sourced from the IDENTITY so a `--negative` row
    // rewriting `service_id` moves what a guard grades and not which peer a
    // phase is waiting for.
    e.dut_service_id = cfg.someip_dut.service_id;
}

}  // namespace tc8
