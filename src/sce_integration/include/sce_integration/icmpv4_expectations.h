#pragma once

#include <cstdint>

namespace tc8 {

// Flat DTO for the expected values a TC8 §4.3 ICMPv4 case compares
// observed Echo Reply fields against. Carries the topology-pinned IPv4
// identity plus the Echo identifier/sequence the tester injected via its
// stimulus, both supplied by the operator via
// `--expect icmpv4.<key>=<value>` (see `cli/expect_parser.cpp`).
//
// Mirror of the ARP / SOME/IP DTOs: lives in its own header so
// `test_config.h` can aggregate it without pulling in the full
// `Icmpv4Expected` Named Context layout. ADL-dispatched helpers on the
// Named Context types include `test_config.h` without a cycle.
//
// The `echo_id` / `echo_seq` values carry the same drift-safety contract
// as the ARP `tester_mac*` constants: the stimulus builder hardcodes the
// literal (`kIcmpEchoId` / `kIcmpEchoSeq` in `stimulus/icmpv4_builder.h`)
// so `--negative` can flip the expectation to prove the SCXML mismatch
// path without also changing what the stimulus sends. `smoke-test.sh`
// must pass a literal matching the builder constant under `--expect
// icmpv4.echo_id=...`; any drift silently turns a positive test into a
// false pass, so edit both together.
struct Icmpv4Expectations {
    std::uint32_t tester_ip    = 0;  // network byte order
    std::uint32_t dut_iface_ip = 0;  // network byte order
    std::uint16_t echo_id  = 0;      // TYPE_09 identifier expectation
    std::uint16_t echo_seq = 0;      // TYPE_09 sequence expectation
};

}  // namespace tc8
