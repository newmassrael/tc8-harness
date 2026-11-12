#pragma once

#include <cstdint>
#include <string>

namespace tc8::stimulus {

// The SOME/IP-SD multicast group this run's DUT discovers on, in network byte order:
// the address the tester's multicast Finds and Offers go to, and the destination half
// of the tester's multicast Session stream (stimulus/sd_session.h).
//
// WHY THIS EXISTS
// ---------------
// The group is a site fact, not a protocol constant. SOME/IP-SD names no fixed group;
// the DUT's configuration chooses one (vsomeip.json `service-discovery.multicast`), and
// a deployment's written specification may mandate another than the one the harness's
// own reference DUT uses (`tc8::dut::kSdMcastGroup`). Half of the harness already read
// the run's value: the orchestrator forwards the DUT's group as `someip.sd_multicast_ip`,
// the verdicts compare against it and the capture joins it. The tester's own SD sends
// still went to the compiled group, so against a DUT on another group its Finds and
// Offers reached nobody, and its Session counter advanced a stream the DUT never saw.
//
// WHY IT IS SET, NOT PASSED
// -------------------------
// For the reason `setSiteDutIpv4` gives (stimulus/site_target.h): every SD emitter
// needs it and nearly no case names one, so the runner publishes it once, at the seam
// every case's stimulus is dispatched through (`ITestRunner::kickStimulus`), and the
// emitters read it. A case that sends to another group on purpose still names it at
// the send.
//
// Process-scoped because the fact is: one harness process runs one case against one
// DUT. Unlike the DUT address it is held atomically: a responder thread a case arms
// can send SD (an Ack, an Offer answer) while the main thread runs, and reading the
// group there must not depend on which of the two touched it first.

// Publish the run's SD group. 0 means the run named none, and the compiled default
// (`tc8::dut::kSdMcastGroup`) applies again.
void setSdMulticastGroup(std::uint32_t group_be);

// The run's SD group: the value published above, or the compiled default when none was.
// Never 0. A consumer that draws its own SD Sessions keys its multicast stream on this,
// not on a copy of the default.
std::uint32_t sdMulticastGroupBe();

// The same group in dotted-quad form, for the socket-level senders that take one.
std::string sdMulticastGroup();

}  // namespace tc8::stimulus
