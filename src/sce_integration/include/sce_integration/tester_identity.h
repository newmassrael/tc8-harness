#pragma once

#include <cstdint>

namespace tc8 {

// The TESTER's own wire identity — addresses this side HOLDS, as opposed to
// addresses it compares an observed frame against. Mirror of `DutIdentity`, and
// the distinction is the same one: identity is what a stimulus BUILDS a frame
// from, an expectation is what an SCXML guard grades the answer with, and a
// `--negative` row rewrites only the latter.
//
struct TesterIdentity {
    // The tester's PRIMARY address, network byte order. What a stimulus puts in
    // a frame it builds; never what a guard grades.
    //
    // ⚠ `ipv4.tester_ip` holds the same value and is the OTHER job: 167 case
    // SCXMLs compare an observed frame against `expected.tester_ip`. Until
    // 2026-09-26 one field did both, and the cost was precise — a
    // `--negative ipv4.tester_ip=…` row moved the grading and the destination
    // together, so the DUT was asked to answer an address nobody held and the
    // case reported a non-conclusion instead of the declared fail. The most
    // graded field in the tree was the one whose guard could not be shown to be
    // load-bearing (docs/tech-debt.md TD-52).
    //
    // The same wall, measured on a case rather than reasoned about:
    // SOMEIPSRV_ONWIRE_01 grades the two fields its request is addressed to, and
    // both candidate flips landed on `inconclusive:no_response_within_listen_window`.
    std::uint32_t ip = 0;

    // A SECOND address the tester answers on, network byte order, or 0 for a
    // tester with only its primary. Populated by `--expect tester.secondary_ip`,
    // emitted by the topology that provisions it: the netns topologies alias
    // 172.16.0.4 onto the tester veth, and a host-NIC site names whatever its
    // operator configured (`site.wire.tester_alias_ip`).
    //
    // It exists because §4.6.5.5 UDP_USER_INTERFACE_08 asks the DUT to send TO a
    // caller-specified destination, which is only observable if the tester holds
    // a second address to choose. The ask used to be the compiled constant
    // `kTesterAliasIp4Be` while the SCXML graded against `ipv4.tester_alias_ip`,
    // so a site naming its own alias moved the grading and not the ask, and the
    // DUT was told to send somewhere nobody was listening.
    //
    // ⚠ Deliberately NOT `ipv4.tester_alias_ip`, which holds the same value and
    // is not the same thing: that one is the expectation
    // `--negative ipv4.tester_alias_ip=10.99.99.99` flips to prove UI_08's guard
    // is load-bearing. Sourcing the ask from it would move both sides together
    // and make that negative vacuous.
    std::uint32_t secondary_ip = 0;
};

}  // namespace tc8
