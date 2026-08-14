#pragma once

#include <string>

#include <CLI/CLI.hpp>

namespace tc8::cli {

// `tc8-harness sd-probe` — does the tester actually HEAR the DUT's SOME/IP
// Service Discovery?
//
// WHY THIS IS A SEPARATE PROBE FROM `ut-ping`
// -------------------------------------------
// A topology preflight can prove a DUT is reachable without proving any verdict
// it is about to reach means anything. Measured on a two-machine `ssh-remote`
// bring-up: SSH, the remote binaries, ICMP to the DUT, and a spawned DUT whose
// Upper Tester answered ALL passed, while the DUT emitted not one SD frame on
// any interface — its host was missing a multicast route on the test NIC, and
// vsomeip gates external routing on a netlink route whose output interface holds
// the configured unicast address. Every SOME/IP case then reported the DUT
// silent, which reads as a DUT defect and was not one.
//
// `ut-ping` is structurally unable to catch that: the Upper Tester is unicast
// UDP, and unicast was the transport that worked. This probe watches the leg
// that was broken, and it watches it the way every verdict does — passively,
// from the tester's own capture — rather than by reading the DUT host's routing
// table over SSH. Inferring the mechanism would test our diagnosis of one fault;
// observing the frame tests the precondition itself, and stays correct on a site
// whose topology satisfies the routing gate some other way.
//
// PASSIVE, WITH ONE DELIBERATE EMISSION
// -------------------------------------
// Nothing is sent to the DUT. The probe does join the SD multicast group for as
// long as it listens, for the reason `tc8::capture::MulticastMembership`
// documents at length: a passive pcap emits no IGMP report, so a snooping bridge
// prunes the group one hop short of the capture and "we heard nothing" stops
// being a statement about the DUT. That is also why an unheld group downgrades
// this probe to "could not run" rather than "the DUT is mute" — see the exit
// codes below.
//
// Exit codes are three-valued on purpose. A preflight must be able to tell
// "the environment is not ready" from "the DUT is at fault", which is the whole
// reason the caller runs a preflight at all; collapsing the two into a boolean
// would recreate the ambiguity this probe exists to remove. The orchestrator's
// ssh-remote preflight pins the three values (`topology::dut::probe::SdEgress`
// in dut/env/orchestrator) — change one side and the other must follow.
class SdProbeCommand {
public:
    explicit SdProbeCommand(CLI::App &app);

    bool parsed() const {
        return sub_->parsed();
    }

    int run();

    // At least one SD frame from the DUT reached the tester on the SD group.
    static constexpr int kObserved = 0;
    // The listen window elapsed with the group held and nothing heard — the DUT
    // (or its host) did not put SD on the wire the tester is on.
    static constexpr int kNotObserved = 1;
    // The probe could not establish what it needed to conclude anything: a bad
    // address, a capture that would not open, or a multicast group it could not
    // hold. NOT a statement about the DUT.
    static constexpr int kCouldNotRun = 2;

private:
    CLI::App *sub_ = nullptr;
    std::string iface_;
    std::string dut_ip_;
    std::string sd_group_;    // empty → tc8::dut::kSdMcastGroup
    std::string ready_file_;  // empty → no readiness signal
    int port_ = 0;            // 0 → tc8::dut::kSdPort
    int timeout_ms_ = 5000;
    bool multicast_membership_ = true;
};

}  // namespace tc8::cli
