#pragma once

#include "arp_expectations.h"
#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying topology-pinned identity supplied via
// CLI `--expect arp.<key>=<value>`. Matching SCXML declaration:
//   <sce:context id="expected" cpp:type="tc8::ArpExpected"
//                cpp:include="sce_integration/arp_expected.h"/>
//
// ARP_13/14/15 read these from their SCXML guards, e.g.
//
//   cond="cpp:captured.sender_proto_ip == expected.dut_iface_ip"
//
// Default 0 is never a valid topology endpoint, so a case landing here
// with expectations unset will fall into its `fail_*` sink — the failure
// reason plus the CLI banner lets the operator notice the missing
// configuration without another layer of validation plumbing.
//
// ARP_07..12 don't read expected values (they compare against RFC 826
// constants directly in their SCXML), but still declare this context so
// the SCE codegen emits a uniform two-arg state-machine constructor. The
// trade-off matches the §5.1 SOMEIPSRV split (FORMAT_01..13 also declare
// the unused expected context).
// Inherits every field from the ArpExpectations DTO (data-only base), so the
// fields are declared once and the DTO and this Named Context cannot drift —
// which also removes the prior `tester_linklocal_ip` default mismatch (the base
// 169.254.1.2 default is now the single source). Add a new `--expect arp.`
// field to ArpExpectations (plus the expect_parser.cpp key table);
// applyTestConfig copies the whole base in one assignment.
struct ArpExpected : ArpExpectations {};

inline void applyTestConfig(ArpExpected &e, const TestConfig &cfg) {
    static_cast<ArpExpectations &>(e) = cfg.arp;
}

}  // namespace tc8
