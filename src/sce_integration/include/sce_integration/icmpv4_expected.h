#pragma once

#include "icmpv4_expectations.h"
#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying topology-pinned identity supplied via
// CLI `--expect icmpv4.<key>=<value>`. Matching SCXML declaration:
//   <sce:context id="expected" cpp:type="tc8::Icmpv4Expected"
//                cpp:include="sce_integration/icmpv4_expected.h"/>
//
// §4.3.3.2 ICMPv4_TYPE_09 reads `expected.echo_id` / `expected.echo_seq`
// from its guards:
//
//   cond="cpp:captured.type == 0 and captured.echo_id == expected.echo_id
//         and captured.echo_seq == expected.echo_seq"
//
// Default 0 is never a valid per-case identifier, so a case landing here
// with expectations unset would fall into its `fail_*` sink — the
// failure reason plus the CLI banner lets the operator notice the
// missing configuration without another layer of validation plumbing.
//
// ICMPv4_TYPE_08 / _10 don't read `echo_id` / `echo_seq` from expected
// (TYPE_08 compares payload bytes against a fixed spec literal, TYPE_10
// asserts absence), but still declare this context so the SCE codegen
// emits a uniform two-arg state-machine constructor. The trade-off
// matches the §5.1 SOMEIPSRV split (FORMAT_01..13 also declare the
// unused expected context).
// Inherits every field from the Icmpv4Expectations DTO (data-only base), so the
// fields are declared once and the DTO and this Named Context cannot drift.
// Add a new `--expect icmpv4.` field to Icmpv4Expectations (plus the
// expect_parser.cpp key table); applyTestConfig copies the base in one
// assignment.
struct Icmpv4Expected : Icmpv4Expectations {};

inline void applyTestConfig(Icmpv4Expected &e, const TestConfig &cfg) {
    static_cast<Icmpv4Expectations &>(e) = cfg.icmpv4;
}

}  // namespace tc8
