#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "tc8/pollable_service.h"

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
// Lifetime is RAII. The constructor opens a non-blocking AF_PACKET RX socket
// bound to `iface` (ETH_P_ARP, so the kernel pre-filters to ARP frames); the
// destructor closes it. There is NO worker thread: the responder is driven by
// the capture loop, which folds pollFd() into its drain set and calls
// onReadable() to answer pending Requests on the SAME thread as frame dispatch
// (no capture/emit concurrency). Requires CAP_NET_RAW (granted to the harness
// binary via the POST_BUILD setcap, same as `sendRawEthernet`).
//
// OWNERSHIP: the responder must stay alive for the whole post-stimulus capture
// window — the DUT ARP-resolves the source IP only when it goes to send its
// Response, which is AFTER `kickStimulus` returns. A `Traits::stimulus` local is
// destroyed before that window opens, so the case hands the responder to the
// runner via `IBackgroundServiceOwner::adoptService`; `ArpResponder` models
// `tc8::IPollableService` for exactly this. See `tc8/pollable_service.h` for the
// seam rationale. (It is also exercised standalone: the privileged netns test
// owns it by value and drives onReadable() itself.)
//
// Non-copyable: it owns a live socket fd.
class ArpResponder : public ::tc8::IPollableService {
public:
    ArpResponder(std::string_view iface, std::vector<ArpBinding> bindings);
    ~ArpResponder();

    ArpResponder(const ArpResponder &) = delete;
    ArpResponder &operator=(const ArpResponder &) = delete;

    // False if the AF_PACKET socket could not be set up. The case checks this
    // before adopting the responder and should surface the failure (inconclusive)
    // rather than assume the DUT's ARP will be answered. A !ok() responder reports
    // pollFd() == -1, so the capture loop simply skips it if adopted anyway.
    bool ok() const { return ok_; }

    // tc8::IPollableService — folded into the capture loop's drain set.
    int pollFd() const override { return sock_; }

    // Drain every ARP frame queued on the socket, answering each matching
    // Request. Runs on the capture-loop thread; non-blocking, returns once drained.
    void onReadable() override;

    // Count of ARP Replies sent so far. Lets a test assert the responder actually
    // answered. Written only in onReadable() (the capture thread), so it needs no
    // synchronisation.
    std::uint64_t repliesSent() const { return replies_sent_; }

private:
    std::string iface_;
    std::vector<ArpBinding> bindings_;
    int sock_ = -1;
    bool ok_ = false;
    std::uint64_t replies_sent_ = 0;
};

}  // namespace tc8::stimulus
