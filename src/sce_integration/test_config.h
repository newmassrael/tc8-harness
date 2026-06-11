#pragma once

#include "arp_expectations.h"
#include "dhcpv4_expectations.h"
#include "icmpv4_expectations.h"
#include "ipv4_expectations.h"
#include "someip_expectations.h"
#include "stimulus/someip_sd_builder.h"

namespace tc8 {

// Aggregate of per-protocol configuration the CLI parses from its flags
// and hands to the factory that builds each `ITestRunner`. Grows by
// addition, not edit: a new protocol family (ARP, DHCP, ICMP, ...) drops
// its own expectations DTO in here alongside the SOMEIP one.
//
// The interface is deliberately data-only. Per-protocol application
// logic lives next to the relevant Named Context as an ADL-findable
// `applyTestConfig(ProtocolContext&, const TestConfig&)` free function;
// `TestRunner<SM>` calls it once at construction. A case whose Context
// type has no matching overload in its namespace fails at compile time,
// which is the forcing function to remember adding one.
//
// `stimulus_timing` is read by stimulus-driven cases (FORMAT_12/13 today)
// so the CLI can override DUT-tuning defaults via `--stimulus-wait`,
// `--stimulus-retry`, `--stimulus-emits`. Defaults are the same as
// `BootTiming{}` and suit the tc8-dut bootstrap; real DUTs with
// slower/faster SD init are expected to override.
struct TestConfig {
    SomeIpExpectations someip{};
    ArpExpectations arp{};
    Icmpv4Expectations icmpv4{};
    Ipv4Expectations ipv4{};
    Dhcpv4Expectations dhcpv4{};
    ::tc8::stimulus::BootTiming stimulus_timing{};
};

}  // namespace tc8
