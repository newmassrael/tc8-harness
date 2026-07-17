#pragma once

// netpacket/packet.h (glibc), NOT linux/if_packet.h: both declare sockaddr_ll
// and packet_mreq, so a TU that pulls in both fails to compile. The tree is
// split — dut/dut_service speaks glibc, src/stimulus speaks the kernel UAPI —
// so a shared header must pick one and its callers must stop naming the other.
// Owning the packet-socket details here is what lets them: a caller that only
// emits frames no longer needs either spelling.
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace tc8::net {

// A send-only AF_PACKET SOCK_RAW socket for one interface, opened once and
// reused for every frame — the single home for "put this Ethernet frame on that
// link".
//
// It exists because the cost of NOT reusing it is invisible and large. Three
// call sites (the DUT's DHCPv4 client, the DUT's link-local autoconf, the
// tester's ARP stimulus) each hand-rolled the same
// socket()+ioctl()+sendto()+close() per message. That close() is not free: the
// kernel runs a `synchronize_net()` RCU grace period, measured on the reference
// host at p50 32 ms (max 60 ms) — `socket()` itself is ~0.01 ms, so the whole
// cost is the teardown.
//
// For an emitter that forms one leg of a timed cadence the placement is fatal:
// the cost falls BETWEEN the wire `sendto` and the start of the next interval's
// timer, so every measured gap carries a systematic +32 ms. That is how a legal
// RFC 2131 §4.1 retransmission draw of 5000 ms reached the wire as 5028 ms and
// failed a [3, 5] s assertion ~1.6% of the time — read as a flake for weeks,
// and quarantined instead of fixed.
//
// Protocol 0, deliberately NOT ETH_P_ALL. A long-lived ETH_P_ALL socket would
// queue every packet on the host into a receive buffer nothing ever drains; the
// per-message versions got away with ETH_P_ALL only by closing immediately. 0
// receives nothing and sends identically: SOCK_RAW transmits the caller's frame
// verbatim and takes the egress link from `sockaddr_ll::sll_ifindex`, so the
// socket's protocol is never consulted on the send path.
//
// Header-only, and here rather than in tc8_wire: tc8_wire is deliberately
// syscall-free so the lwIP DUT port can link it, and this is nothing but
// syscalls. Header-only keeps it from becoming a cross-program link artifact
// for its callers — the same shape, and the same reasoning, as `rtnetlink.h`
// next door.
//
// NOT thread-safe: every owner drives it from a single thread (the DUT's worker
// / the tester's stimulus call). Re-binding is automatic — `send` reopens when
// the interface name changes, so an owner never has to remember to invalidate.
class RawPacketSocket {
public:
    RawPacketSocket() = default;
    ~RawPacketSocket() {
        close();
    }
    RawPacketSocket(const RawPacketSocket &)            = delete;
    RawPacketSocket &operator=(const RawPacketSocket &) = delete;

    // Put `frame` (a complete Ethernet frame — the destination MAC is read from
    // its first 6 bytes) on `iface`. Opens the socket on first use and reuses it
    // for as long as `iface` is unchanged.
    //
    // Returns 0 on success, or a negative code identifying the failed step:
    // -1 socket(), -2 SIOCGIFINDEX, -3 sendto(). Callers historically ignore the
    // value (an emit failure surfaces as the SCXML's absence deadline rather
    // than a DUT crash), so the codes stay distinct for diagnosis rather than
    // control flow.
    int send(std::string_view iface, const std::uint8_t *frame, std::size_t len) {
        if (sk_ < 0 || bound_iface_ != iface) {
            close();
            sk_ = ::socket(AF_PACKET, SOCK_RAW, 0);
            if (sk_ < 0) {
                return -1;
            }
            ifreq ifr{};
            std::strncpy(ifr.ifr_name, std::string(iface).c_str(), IFNAMSIZ - 1);
            if (::ioctl(sk_, SIOCGIFINDEX, &ifr) < 0) {
                close();
                return -2;
            }
            ifindex_     = ifr.ifr_ifindex;
            bound_iface_ = std::string(iface);
        }

        sockaddr_ll dest{};
        dest.sll_family  = AF_PACKET;
        dest.sll_ifindex = ifindex_;
        dest.sll_halen   = 6;
        // Link-layer destination, mirrored from the frame's own eth-dst so the
        // two cannot disagree. The kernel uses it on links that require it; for
        // raw injection on veth the header in the frame is authoritative.
        // Bounded by `len`: an under-6-byte runt must not be read past its end
        // (one of the two merged implementations copied 6 unconditionally).
        std::memcpy(dest.sll_addr, frame, len < 6 ? len : 6);
        // EtherType from the Ethernet-II header at 12..13, so this works for any
        // L2 frame a caller builds (ARP 0x0806, IPv4 0x0800, ...). sll_protocol
        // is only a hint the kernel hands drivers that filter/offload by
        // ethertype — for raw injection the frame's own field is authoritative —
        // but keeping it aligned avoids ambiguity across kernel versions. A
        // runt shorter than the header keeps 0, the same as an unset field.
        if (len >= 14) {
            dest.sll_protocol = static_cast<std::uint16_t>(
                htons(static_cast<std::uint16_t>((frame[12] << 8) | frame[13])));
        }
        const ssize_t rc = ::sendto(sk_, frame, len, 0,
                                    reinterpret_cast<sockaddr *>(&dest), sizeof(dest));
        // A short write is a failed emit, not a partial one a caller could
        // resume: the frame either reached the link whole or it did not. One of
        // the two merged implementations checked this and the other did not.
        return (rc < 0 || static_cast<std::size_t>(rc) != len) ? -3 : 0;
    }

    // Idempotent. Callers rarely need it — the destructor covers the normal
    // path and `send` re-binds itself on an interface change.
    void close() {
        if (sk_ >= 0) {
            ::close(sk_);
            sk_ = -1;
        }
        ifindex_ = -1;
        bound_iface_.clear();
    }

private:
    int         sk_      = -1;
    int         ifindex_ = -1;
    std::string bound_iface_;
};

}  // namespace tc8::net
