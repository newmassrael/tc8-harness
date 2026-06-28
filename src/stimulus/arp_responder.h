#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace tc8::stimulus {

// One IPv4 -> MAC binding the responder answers ARP Requests for. `ip_be` is a
// 32-bit IPv4 address in network byte order (the same convention
// `ipv4OfInterface` / `inet_pton` produce, and that `ArpFrame::target_proto_ip`
// is compared in), so a binding built from a configured tester IP matches a
// captured Request's Target Protocol Address byte-for-byte regardless of host
// endianness.
struct ArpBinding {
    std::uint32_t ip_be;              // target IPv4 the responder claims
    std::array<std::uint8_t, 6> mac;  // sender hardware address advertised in the Reply
    // `mac` MUST equal the Ethernet source MAC the tester puts on the frames it
    // sends FROM `ip_be` (e.g. emitMethodRequestFromSourceIp's `src_mac`): the
    // DUT resolves `ip_be` -> this `mac`, then a stack that snoops the request's
    // `eth_src` and one that uses the resolved entry must agree, else the
    // Response is addressed to a MAC the tester is not on and the case goes
    // silently inconclusive. Source BOTH from `macOfInterface(iface)`.
};

// Build the Ethernet-II + ARP Reply that answers `request_frame` (a raw,
// captured L2 frame of `len` bytes) when its ARP Target Protocol Address
// matches one of `bindings`. Pure (no I/O), so the match decision and reply
// wire-layout are unit-testable. Returns std::nullopt when the frame is not an
// Ethernet+IPv4 ARP *Request*, is malformed/truncated, or targets an IP that
// no binding claims.
//
// The Reply follows RFC 826 §2 (Packet Reception):
//   - opcode 2; sender = (matched binding ip, matched binding mac)
//   - target = the requester's sender pair, so the answer is a unicast
//   - Ethernet dst = requester's sender_hw, Ethernet src = the binding mac
// The frame is assembled via `buildArpFrame`, so the ARP wire layout has a
// single source of truth shared with the tester-emit builders. VLAN-tagged
// requests (EtherType 0x8100) are not matched — the spoofed-source-IP RPC
// scenario this serves is untagged; an OEM VLAN profile would extend the
// EtherType check here.
std::optional<std::vector<std::uint8_t>>
buildArpReplyForRequest(const std::uint8_t *request_frame, std::size_t len,
                        const std::vector<ArpBinding> &bindings);

// A background ARP responder: answers ARP Requests for `bindings` on `iface`
// so a DUT can resolve a tester-spoofed source IP and unicast its Response
// back to the tester. Unlike a gratuitous ARP announcement — which Linux
// ignores for neigh-cache *creation* unless sysctl `arp_accept=1` is set on
// the receiving interface — answering the DUT's actual Request is RFC 826 §2
// reception that populates the cache on any conformant host, so this works
// independent of the DUT's `arp_accept` setting.
//
// Lifetime is RAII. The constructor opens an AF_PACKET RX socket bound to
// `iface` (ETH_P_ARP, so the kernel pre-filters to ARP frames), arms an
// eventfd waker, and spawns a worker thread that `poll()`s {socket, waker} and
// replies to matching Requests until the destructor signals the waker and
// joins the thread. Requires CAP_NET_RAW (granted to the harness binary via
// the POST_BUILD setcap, same as `sendRawEthernet`).
//
// This is a deliberately joinable, stop-signalled worker — NOT the detached-
// thread stimulus anti-pattern the scheduler replaced. A detached thread could
// be SIGKILLed mid-emit and leak across the poll-loop boundary; this thread is
// owned, woken deterministically, and joined in the destructor, so teardown is
// race-free.
//
// OWNERSHIP: the responder must stay alive for the whole post-stimulus capture
// window — the DUT ARP-resolves the source IP only when it goes to send its
// Response, which is AFTER `kickStimulus` returns and the poll loop is running
// (see test_runner.h). It therefore needs an owner that outlives `kickStimulus`:
// a `Traits::stimulus` local will NOT do (it is destroyed before the poll loop
// starts), and `IStimulusScheduler` has no object-holding API to repurpose for
// this. The in-tree owner seam — a runner-held background-service list, or
// folding the responder's pollable fd into the CLI poll loop so no separate
// thread is needed at all — is intentionally deferred until the first in-tree
// consumer lands (the sole consumer today is an out-of-tree OEM case). Until
// then the class is exercised standalone: the privileged netns test owns it by
// value for the duration of its own capture loop.
//
// Non-copyable and non-movable: it owns a running thread and live fds.
class ArpResponder {
public:
    ArpResponder(std::string_view iface, std::vector<ArpBinding> bindings);
    ~ArpResponder();

    ArpResponder(const ArpResponder &) = delete;
    ArpResponder &operator=(const ArpResponder &) = delete;

    // False if the AF_PACKET socket / eventfd could not be set up (the worker
    // never started). The caller then has no responder and should surface the
    // failure rather than assume the DUT's ARP will be answered.
    bool ok() const { return ok_; }

    // Count of ARP Replies the worker has sent so far. Lets a test assert the
    // responder actually answered, not merely that it stayed alive. Relaxed
    // ordering: a monotonic counter with no other state to synchronise.
    std::uint64_t repliesSent() const {
        return replies_sent_.load(std::memory_order_relaxed);
    }

private:
    void run();

    std::string iface_;
    std::vector<ArpBinding> bindings_;
    int sock_ = -1;
    int wake_fd_ = -1;
    bool ok_ = false;
    std::atomic<std::uint64_t> replies_sent_{0};
    std::thread worker_;
};

}  // namespace tc8::stimulus
