#pragma once

#include <cstdint>

namespace tc8::stimulus {

// The DUT's IPv4 on the test link, in network byte order — the address the
// tester sends *to* when a stimulus needs a unicast destination and the case
// did not name one itself.
//
// WHY THIS EXISTS
// ---------------
// A SOME/IP unicast stimulus (Subscribe, and the SD messages built on it) has
// to be addressed to the DUT. That address is a per-run topology fact, and the
// harness already has exactly one home for it: `TestConfig::dut.ip`, which
// `dut_identity.h` designates as the domain-neutral SSOT "every protocol's
// stimulus path" targets. Every other protocol reads it (`cfg.dut.ip` is passed
// explicitly by the ARP / IPv4 / fault-injection emitters).
//
// SOME/IP did not. `SubscribeDestination::ipv4_be` instead carried a
// compile-time default of 172.16.0.2 — the address of the reference DUT in the
// single-pc netns. On netns that literal happens to BE the DUT, so every case
// passed; on any real two-machine site it is an address that belongs to nobody,
// and the Subscribe left via the DEFAULT ROUTE instead of the test link.
// Measured on a real site: `ip route get 172.16.0.2` resolved to the LAN
// gateway over WiFi, the test wire carried zero frames to it, and 24 SOMEIPSRV
// cases reported `no_ack_within_listen_window` — a wire-shaped symptom with no
// wire fault behind it.
//
// WHY IT IS SET, NOT PASSED
// -------------------------
// 51 case headers reach the SD emitters, and only a handful name a destination.
// Handing the correct address to fifty-one case authors is the shape of
// invariant that gets forgotten — the same reasoning that keeps the
// absence-pass rule in the one place that emits the verdict rather than in each
// case's guard. So the runner publishes it ONCE, at the single point every
// case's stimulus is dispatched through (`ITestRunner::kickStimulus`), and the
// emitters resolve an unset destination from it. A case that genuinely targets
// something else still says so explicitly and is unaffected.
//
// Process-scoped because the fact is: one harness process runs one case against
// one DUT. There is no configuration in which two values are live at once.
void setSiteDutIpv4(std::uint32_t ipv4_be);

// The address set above, or 0 when the process never learned one (a caller
// outside the runner — e.g. a standalone tool). 0 is "unknown", never a usable
// address, and callers must fail loudly rather than send to 0.0.0.0.
std::uint32_t siteDutIpv4();

}  // namespace tc8::stimulus
