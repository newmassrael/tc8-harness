#pragma once

#include <cstddef>
#include <cstdint>

namespace tc8::stimulus {

// The SOME/IP-SD Session ID and Reboot flag the tester sends, one counter per stream.
//
// WHY THIS EXISTS
// ---------------
// A receiver keeps one SD Session per sender and per unicast / multicast stream
// (PRS_SOMEIPSD_00503) and reads "old Reboot set, new Reboot set, old Session >= new
// Session" as a REBOOT of that sender: it expires the sender's services and
// subscriptions and forgets the stored Session. The tester used to let each emitter pick
// its own Session (the boot Find counted from 1 on every call, the multi-entry Subscribe
// always sent 1, every other emitter took what its caller passed), so two emitters on one
// stream announced a reboot nobody meant. Measured in one full consumer SOME/IP run: the
// target logged a tester reboot in 20 of 414 cases, and in four of them the reboot tore
// down the very state the verdict then judged, so the case could not tell a correct
// target from one lacking the property.
//
// THE RULE
// --------
// A stream is (tester source IPv4, destination IPv4): the destination is the SD multicast
// group for the multicast stream and the receiver's address for a unicast one, which is
// exactly the receiver's (sender, unicast | multicast) slot. Each stream counts from
// kSdSessionFirst with Reboot set, adds one per SD message, and wraps 0xFFFF -> 0x0001,
// where the Reboot flag clears (SD §4.2.1).
//
// Every tc8 SD emitter draws from this counter when its caller leaves the Session unset
// (the default of every `session_id` field). A Session the caller sets is sent as given,
// and the stream continues from it: that is how a case announces a reboot or repeats a
// Session on purpose, and the next default message follows on from that value instead of
// undoing it. A reboot is something a case asks for, never a side effect.
//
// WHERE THE COUNTER LEARNS WHAT WAS SENT
// --------------------------------------
// From the UDP send primitives (sendUdpUnicast / sendUdpMulticast / sendUdpFromSourceIp),
// after a successful send of a datagram that carries the SD Message ID, for the reason
// tx_observer.h reports there: a consumer that builds and sends raw SD by a route no
// emitter wraps is still seen, so its Session moves the stream as well. A Session handed
// out by nextSdSession and then sent is recognised as such and does not move the counter
// back, even when two threads (a case and a responder) send on one stream. A chosen
// Session ends that recognition for every draw not yet sent when it goes out: a draw
// still in flight when another thread sends a chosen Session on the same stream then
// reads as chosen too.
//
// SCOPE
// -----
// Process-scoped for the reason setSiteDutIpv4 is: one harness process runs one case, so
// the counters start fresh for every case. The stimulus of a case runs once per process
// even when the case repeats its procedure, and a repeat must continue the stream, not
// restart it.

// The first Session of a stream (SD §4.2.1; the wrap goes to 0x0001, never to 0x0000).
inline constexpr std::uint16_t kSdSessionFirst = 0x0001;

struct SdSession {
    std::uint16_t session_id = kSdSessionFirst;
    bool reboot = true;  // the SD header Reboot flag to send with it
};

// The next Session of the stream from `src_ipv4_be` to `dst_ipv4_be` (both network byte
// order; `dst_ipv4_be` is the multicast group for the multicast stream), and the Reboot
// flag that goes with it. Advances the stream. For a consumer that builds SD itself (an
// Ack responder, a second simulated source address): draw here, put the Session in the
// SOME/IP header and the flag into the SD flags byte with sdFlagsWithReboot, and send
// through any of the UDP primitives.
SdSession nextSdSession(std::uint32_t src_ipv4_be, std::uint32_t dst_ipv4_be);

// `flags` with its Reboot bit set to `reboot`; every other bit (Unicast, the reserved
// bits a case may set) kept as given.
std::uint8_t sdFlagsWithReboot(std::uint8_t flags, bool reboot);

// The send primitives' report: `datagram` (the UDP payload) went from `src_ipv4_be` to
// `dst_ipv4_be`. A datagram without the SD Message ID is ignored. A Session this stream
// handed out is retired; any other Session is one the sender chose, and the stream
// continues from it with the Reboot flag it carried.
void noteSdDatagramSent(std::uint32_t src_ipv4_be, std::uint32_t dst_ipv4_be,
                        const std::uint8_t *datagram, std::size_t size);

// Forget every stream. For a test that runs several scenarios in one process; the harness
// itself never needs it (see SCOPE).
void resetSdSessions();

}  // namespace tc8::stimulus
