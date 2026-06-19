#include "linklocal_autoconf.h"

#include "wire/ip_checksum.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <random>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace tc8::dut {

namespace {

constexpr std::uint16_t kEthTypeIp4 = 0x0800;
constexpr std::uint16_t kEthTypeArp = 0x0806;

constexpr std::array<std::uint8_t, 6> kEthBroadcast{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
constexpr std::array<std::uint8_t, 6> kEthZero{0, 0, 0, 0, 0, 0};

// 169.254.0.0 in NBO. Used to derive picked LL addresses by ORing
// with a 16-bit random suffix (X in [1, 254], Y in [0, 255]).
constexpr std::uint32_t kLLNetworkBe = 0xA9FE0000U;

using ::tc8::wire::inetChecksum;
using ::tc8::wire::udpChecksum;
using ::tc8::wire::writeBe16;

}  // namespace

LinklocalAutoconf::LinklocalAutoconf() = default;

LinklocalAutoconf::~LinklocalAutoconf() {
    abort();
}

void LinklocalAutoconf::bind(std::string iface,
                              std::array<std::uint8_t, 6> dut_mac,
                              std::uint32_t dut_iface_ip_be) {
    iface_           = std::move(iface);
    dut_mac_         = dut_mac;
    dut_iface_ip_be_ = dut_iface_ip_be;
}

bool LinklocalAutoconf::start(const Params& params) {
    abort();
    stop_requested_.store(false);
    worker_ = std::thread([this, params]() { runLoop(params); });
    return true;
}

void LinklocalAutoconf::abort() {
    stop_requested_.store(true);
    if (worker_.joinable()) {
        worker_.join();
    }
    // worker_ owns the listener thread's lifecycle through runLoop's
    // stopConflictListener calls; the join above guarantees the listener
    // is already torn down by the time we get here. Defensive join in
    // case start() ran but runLoop never reached the listener cleanup.
    stopConflictListener();
    // Same defensive pattern for the post-claim responder thread —
    // runLoop spawns it after Phase 2 commit but worker_ exits while
    // it stays alive. abort() joins via stop_responder_ here.
    stopArpResponder();
    {
        std::lock_guard<std::mutex> lk(address_mu_);
        committed_address_be_ = 0;
    }
}

std::uint32_t LinklocalAutoconf::currentAddressBe() const {
    std::lock_guard<std::mutex> lk(address_mu_);
    return committed_address_be_;
}

std::uint32_t LinklocalAutoconf::pickLLAddress() {
    std::random_device rd;
    std::mt19937 rng(rd());
    // X in [1, 254] avoids reserved 169.254.0.0/24 and 169.254.255.0/24
    // per RFC 3927 §2.1. Y in [0, 255] is unrestricted within X.
    std::uniform_int_distribution<std::uint32_t> x_dist(1, 254);
    std::uniform_int_distribution<std::uint32_t> y_dist(0, 255);
    const std::uint32_t x = x_dist(rng);
    const std::uint32_t y = y_dist(rng);
    return htonl(0xA9FE0000U | (x << 8) | y);
}

int LinklocalAutoconf::sendRaw(const std::uint8_t* frame, std::size_t len) {
    int sk = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sk < 0) return -1;

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface_.c_str(), IFNAMSIZ - 1);
    if (::ioctl(sk, SIOCGIFINDEX, &ifr) < 0) {
        ::close(sk);
        return -2;
    }
    sockaddr_ll dest{};
    dest.sll_family   = AF_PACKET;
    dest.sll_ifindex  = ifr.ifr_ifindex;
    dest.sll_halen    = 6;
    std::memcpy(dest.sll_addr, frame, 6);  // Eth dst from frame head
    ssize_t rc = ::sendto(sk, frame, len, 0,
                          reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    ::close(sk);
    return rc < 0 ? -3 : 0;
}

void LinklocalAutoconf::emitArpProbe(std::uint32_t tentative_ll_be,
                                      LinklocalAutoconfFlavor flavor) {
    // Compliant Probe shape per RFC 3927 §2.1.1. Each field below has
    // a default the spec mandates; `flavor` mutates exactly one of
    // them (and only one) before the frame is serialised, which keeps
    // the negative-case SCXML's verdict mapping unambiguous: every
    // fail_state branch corresponds to a single invariant violation.
    std::array<std::uint8_t, 6> eth_dst      = kEthBroadcast;
    std::array<std::uint8_t, 6> sender_hw    = dut_mac_;
    std::uint32_t               sender_ip_be = 0;
    std::array<std::uint8_t, 6> target_hw    = kEthZero;
    std::uint32_t               target_ip_be = tentative_ll_be;

    // Mutation literals are deliberately well-known constants so a
    // pcap-side reader can recognise the fault-injection variant
    // without consulting source. SenderHw / TargetHw byte sequences
    // are also OUI-private (0xCA / 0xDE leading bit set → locally
    // administered) which avoids any chance of a real-NIC collision
    // on the dev-netns veth pair.
    switch (flavor) {
        case LinklocalAutoconfFlavor::None:
            // Compliant emit — no mutation.
            break;
        case LinklocalAutoconfFlavor::SenderIpNonzero:
            // RFC 3927 §2.1.1: sender_proto_ip MUST be 0. Set to the DUT
            // iface IP so the violation is wire-recognisable.
            sender_ip_be = dut_iface_ip_be_;
            break;
        case LinklocalAutoconfFlavor::TargetOutsidePrefix:
            // RFC 3927 §2.1: target MUST be in 169.254/16. Use 192.168.1.66
            // (RFC 1918 private — distinguishable on capture from
            // any veth-pair management traffic).
            target_ip_be = htonl(0xC0A80142U);
            break;
        case LinklocalAutoconfFlavor::TargetInReservedRange:
            // RFC 3927 §2.1: third octet MUST be in [1, 254]. Use 169.254.0.42
            // (X=0 → in reserved 169.254.0/24 per RFC 3927). Still
            // in 169.254/16 so the prefix-only check (_08) doesn't
            // also fire — the violation is _01-specific.
            target_ip_be = htonl(0xA9FE002AU);
            break;
        case LinklocalAutoconfFlavor::TargetHwNonzero:
            // RFC 3927 §2.2.1: target_hw SHOULD be all zero. Use a locally-
            // administered well-known sentinel.
            target_hw = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00};
            break;
        case LinklocalAutoconfFlavor::SenderHwWrong:
            // RFC 826 §2.2.1 (RFC 826 ar$sha): sender_hw MUST be the iface
            // MAC. Substitute a locally-administered sentinel that
            // is NEVER the DUT iface MAC under any topology so
            // false negatives are impossible.
            sender_hw = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00};
            break;
        case LinklocalAutoconfFlavor::ProbeEthDstUnicast:
            // RFC 3927 §2.1.1: an ARP Probe whose sender_proto_ip is in
            // 169.254/16 MUST be broadcast. Direct the Ethernet dst at
            // the DUT iface MAC instead — a unicast no other host on the
            // link should see (mirrors the Announce-phase
            // AnnounceEthDstUnicast flavor for the Probe shape).
            eth_dst = dut_mac_;
            break;
        // §4.5.6.3 Announce-phase + RFC 3927 §2.5 Reply-phase
        // flavors: Probe phase stays compliant (the spec precondition
        // still has to complete so the SCXML reaches its post-claim
        // listening state).
        case LinklocalAutoconfFlavor::AnnounceEthDstUnicast:
        case LinklocalAutoconfFlavor::AnnounceSenderTargetMismatch:
        case LinklocalAutoconfFlavor::AnnounceSenderHwWrong:
        case LinklocalAutoconfFlavor::AnnounceTargetHwNonzero:
        case LinklocalAutoconfFlavor::ReplySenderIpWrong:
        case LinklocalAutoconfFlavor::ReplyEthDstUnicast:
            break;
    }

    // 14 B Ethernet + 28 B ARP = 42 B
    std::uint8_t f[42] = {};
    std::memcpy(f + 0, eth_dst.data(), 6);          // Eth dst (broadcast; flavor mutates)
    std::memcpy(f + 6, dut_mac_.data(), 6);        // Eth src (always DUT)
    writeBe16(f + 12, kEthTypeArp);                 // Ethertype

    writeBe16(f + 14, 0x0001);                      // hw_type = Ethernet
    writeBe16(f + 16, kEthTypeIp4);                 // proto_type = IPv4
    f[18] = 6;                                       // hw_addr_len
    f[19] = 4;                                       // proto_addr_len
    writeBe16(f + 20, 0x0001);                      // opcode = Request
    std::memcpy(f + 22, sender_hw.data(), 6);       // sender_hw
    std::memcpy(f + 28, &sender_ip_be, 4);          // sender_proto_ip
    std::memcpy(f + 32, target_hw.data(), 6);       // target_hw
    std::memcpy(f + 38, &target_ip_be, 4);          // target_proto_ip

    sendRaw(f, sizeof(f));
}

void LinklocalAutoconf::emitArpAnnounce(std::uint32_t committed_ll_be,
                                         LinklocalAutoconfFlavor flavor) {
    // Compliant Announce shape per RFC 3927 §2.4: ARP Request with
    // sender_ip == target_ip == committed LL, sender_hw == DUT MAC,
    // target_hw == 00:..:00, eth_dst == broadcast. `flavor` mutates
    // exactly one of those fields (and only one) before the frame is
    // serialised, so each negative-case SCXML's verdict mapping
    // corresponds to a single invariant violation.
    std::array<std::uint8_t, 6> eth_dst   = kEthBroadcast;
    std::array<std::uint8_t, 6> sender_hw = dut_mac_;
    std::uint32_t               sender_ip_be = committed_ll_be;
    std::array<std::uint8_t, 6> target_hw    = kEthZero;
    std::uint32_t               target_ip_be = committed_ll_be;

    switch (flavor) {
        case LinklocalAutoconfFlavor::None:
        // §4.5.6.2 Probe-phase + RFC 3927 §2.5 Reply-phase flavors:
        // Announce stays compliant.
        case LinklocalAutoconfFlavor::SenderIpNonzero:
        case LinklocalAutoconfFlavor::TargetOutsidePrefix:
        case LinklocalAutoconfFlavor::TargetInReservedRange:
        case LinklocalAutoconfFlavor::TargetHwNonzero:
        case LinklocalAutoconfFlavor::SenderHwWrong:
        case LinklocalAutoconfFlavor::ProbeEthDstUnicast:
        case LinklocalAutoconfFlavor::ReplySenderIpWrong:
        case LinklocalAutoconfFlavor::ReplyEthDstUnicast:
            break;
        case LinklocalAutoconfFlavor::AnnounceEthDstUnicast:
            // RFC 3927 §2.4 / RFC 3927 §2.5 last MUST: ARP packets whose sender_proto_ip
            // is in 169.254/16 MUST be broadcast. Direct the Ethernet
            // dst at the DUT iface MAC instead — a unicast that no
            // other host on the link should see, but which a
            // non-conformant DUT might emit if it confuses Announce
            // with a Reply.
            eth_dst = dut_mac_;
            break;
        case LinklocalAutoconfFlavor::AnnounceSenderTargetMismatch:
            // RFC 3927 §2.4: Announce sets sender_proto_ip == target_proto_ip
            // == announced LL. Drive sender to the iface IP (a
            // routable, non-LL value distinguishable on capture from
            // the committed LL).
            sender_ip_be = dut_iface_ip_be_;
            break;
        case LinklocalAutoconfFlavor::AnnounceSenderHwWrong:
            // RFC 826 §2.4 (RFC 826 ar$sha): sender_hw MUST be the iface MAC.
            // Same locally-administered sentinel as the Probe-shape
            // SenderHwWrong flavor — distinct OUI from the Probe
            // sentinel keeps pcap-side disambiguation simple.
            sender_hw = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01};
            break;
        case LinklocalAutoconfFlavor::AnnounceTargetHwNonzero:
            // RFC 3927 §2.4: target_hw SHOULD be all zero (the asker is the
            // host itself, not a known target). Use the same locally-
            // administered sentinel as the Probe-shape TargetHwNonzero
            // flavor.
            target_hw = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
            break;
    }

    std::uint8_t f[42] = {};
    std::memcpy(f + 0, eth_dst.data(), 6);
    std::memcpy(f + 6, dut_mac_.data(), 6);
    writeBe16(f + 12, kEthTypeArp);

    writeBe16(f + 14, 0x0001);
    writeBe16(f + 16, kEthTypeIp4);
    f[18] = 6;
    f[19] = 4;
    writeBe16(f + 20, 0x0001);                      // opcode = Request
    std::memcpy(f + 22, sender_hw.data(), 6);       // sender_hw
    std::memcpy(f + 28, &sender_ip_be, 4);          // sender_proto_ip
    std::memcpy(f + 32, target_hw.data(), 6);       // target_hw
    std::memcpy(f + 38, &target_ip_be, 4);          // target_proto_ip

    sendRaw(f, sizeof(f));
}

void LinklocalAutoconf::emitDhcpDiscover() {
    // 14 B Eth + 20 B IPv4 + 8 B UDP + 240 B BOOTP fixed + 7 B DHCP
    // options (msg-type + end + 5 B padding to even DHCP body) = 289 B.
    // Use a 240 B BOOTP fixed body + 4 B options (magic) + 3 B (msg
    // type 53,1,1 + END 0xFF). Round up to keep the wire size simple.
    constexpr std::size_t kBootpFixedLen = 240;       // op..options-magic
    constexpr std::size_t kDhcpOptsLen   = 4;         // 53,1,1, FF
    constexpr std::size_t kDhcpBodyLen   = kBootpFixedLen + kDhcpOptsLen;
    constexpr std::size_t kUdpLen        = 8 + kDhcpBodyLen;
    constexpr std::size_t kIp4Len        = 20 + kUdpLen;
    constexpr std::size_t kFrameLen      = 14 + kIp4Len;

    std::uint8_t f[14 + 20 + 8 + 244] = {};

    // Ethernet: dst=broadcast, src=DUT MAC, ethertype=IPv4
    std::memcpy(f + 0, kEthBroadcast.data(), 6);
    std::memcpy(f + 6, dut_mac_.data(), 6);
    writeBe16(f + 12, kEthTypeIp4);

    // IPv4 header (20 B, no options)
    std::uint8_t* ip = f + 14;
    ip[0] = 0x45;                                        // version=4, IHL=5
    ip[1] = 0x00;                                        // DSCP/ECN
    writeBe16(ip + 2, static_cast<std::uint16_t>(kIp4Len));
    writeBe16(ip + 4, 0x0000);                           // ID
    writeBe16(ip + 6, 0x0000);                           // Flags+FragOff
    ip[8] = 64;                                          // TTL
    ip[9] = 0x11;                                        // proto = UDP
    writeBe16(ip + 10, 0);                               // checksum (later)
    std::uint32_t src_be = 0x00000000U;                  // 0.0.0.0
    std::uint32_t dst_be = 0xFFFFFFFFU;                  // 255.255.255.255
    std::memcpy(ip + 12, &src_be, 4);
    std::memcpy(ip + 16, &dst_be, 4);
    const std::uint16_t ip_csum = inetChecksum(ip, 20);
    writeBe16(ip + 10, ip_csum);

    // UDP header (8 B): src=68, dst=67
    std::uint8_t* udp = ip + 20;
    writeBe16(udp + 0, 68);
    writeBe16(udp + 2, 67);
    writeBe16(udp + 4, static_cast<std::uint16_t>(kUdpLen));
    writeBe16(udp + 6, 0);  // checksum (later)

    // BOOTP fixed body: op=1, htype=1, hlen=6, hops=0; xid; secs;
    // flags; ciaddr/yiaddr/siaddr/giaddr=0; chaddr (6 B MAC + 10 B
    // pad); sname (64 B 0); file (128 B 0); options magic.
    std::uint8_t* bp = udp + 8;
    bp[0] = 1;       // BOOTREQUEST
    bp[1] = 1;       // htype = Ethernet
    bp[2] = 6;       // hlen = 6
    bp[3] = 0;       // hops
    // xid: derive 4 bytes from DUT MAC for stable per-instance value
    std::memcpy(bp + 4, dut_mac_.data(), 4);
    // secs, flags = 0
    // ciaddr/yiaddr/siaddr/giaddr at offsets 12..27 = 0
    // chaddr at offset 28..43: 6 B MAC + 10 B pad
    std::memcpy(bp + 28, dut_mac_.data(), 6);
    // sname (64 B) at 44..107 = 0
    // file (128 B) at 108..235 = 0
    // options magic at 236..239 = 0x63 0x82 0x53 0x63 (RFC 1497)
    bp[236] = 0x63;
    bp[237] = 0x82;
    bp[238] = 0x53;
    bp[239] = 0x63;

    // DHCP options: 53 (Message Type), len 1, value 1 (DHCPDISCOVER); FF
    std::uint8_t* opts = bp + 240;
    opts[0] = 53;
    opts[1] = 1;
    opts[2] = 1;
    opts[3] = 0xFF;  // End

    const std::uint16_t udp_csum = udpChecksum(src_be, dst_be, udp, kUdpLen);
    writeBe16(udp + 6, udp_csum);

    sendRaw(f, kFrameLen);
}

void LinklocalAutoconf::runLoop(Params params) {
    // Publish the fault-injection flavor for the responder thread's
    // defending Reply before any thread is spawned (the spawn is the
    // happens-before barrier; flavor_ is read-only thereafter).
    flavor_ = params.flavor;

    auto sleepInterruptible = [&](std::chrono::milliseconds dur) {
        const auto deadline = std::chrono::steady_clock::now() + dur;
        while (!stop_requested_.load()) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) return;
            const auto step = std::min<std::chrono::milliseconds>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now),
                std::chrono::milliseconds(50));
            std::this_thread::sleep_for(step);
        }
    };

    // Phase 0: emit one DHCPDISCOVER, then sleep dhcp_timeout_ms to
    // model "no DHCP server replied". §4.5 cases observe this Discover
    // as the precondition step "DUT: Sends DHCPDISCOVER Message".
    // DHCPDISCOVER is fired ONCE per `start()` — RFC 3927 §2.5 cease
    // re-enters Phase 1 (new Probe sequence) but does not re-emit
    // DHCPDISCOVER, matching the spec's "configure a new IPv4
    // Link-Local address" wording (the DHCP failure already happened).
    emitDhcpDiscover();
    sleepInterruptible(params.dhcp_timeout_ms);
    if (stop_requested_.load()) return;

    std::random_device rd;
    std::mt19937 rng(rd());
    auto probe_interval = [&]() {
        const auto lo = static_cast<std::uint32_t>(params.probe_min_ms.count());
        const auto hi = static_cast<std::uint32_t>(params.probe_max_ms.count());
        std::uniform_int_distribution<std::uint32_t> dist(
            lo, std::max(lo, hi));
        return std::chrono::milliseconds(dist(rng));
    };

    // Outer loop: each iteration is one full "claim + steady-state
    // until cease" cycle. RFC 3927 §2.5 method 1 (always-cease) drives
    // the loop: a steady-state conflicting ARP raises
    // `cease_requested_`, the iteration tears down the claim, and the
    // next iteration re-enters Phase 1 with a freshly-picked LL.
    // §4.5.6.4 CONFLICT_06..10 verify the cease + reprobe edge.
    while (!stop_requested_.load()) {
        // Phase 1: PROBE with conflict detection. RFC 3927 §2.2.1
        // fixes the conflict window as "from the beginning of the
        // probing process until ANNOUNCE_WAIT seconds after the last
        // probe packet is sent" — listener stays up across PROBE_WAIT
        // + 3 Probes + ANNOUNCE_WAIT. On conflict the host MUST select
        // a new pseudo-random address and repeat the process. Once
        // rfc3927::kMaxConflicts is reached, the host enters
        // rate-limit mode: each subsequent attempt waits
        // RATE_LIMIT_INTERVAL before picking a new address, so
        // emissions are throttled to one new address per interval
        // (RFC 3927 §2.2.1 / RFC 3927 §2.5). §4.5.6.2 _14 verifies the silence.
        // Conflict counter and rate-limit flag are local to the
        // outer-loop iteration: a steady-state cease starts a fresh
        // probing attempt with a clean rate-limit budget, matching
        // RFC 3927's interpretation that MAX_CONFLICTS counts
        // probing-window collisions, not steady-state defenses.
        std::uint32_t tentative_ll_be = 0;
        int conflict_count = 0;
        bool rate_limit_active = false;
        while (true) {
            if (rate_limit_active) {
                sleepInterruptible(params.rate_limit_interval_ms);
                if (stop_requested_.load()) return;
            }

            tentative_ll_be = pickLLAddress();
            startConflictListener(tentative_ll_be);

            sleepInterruptible(params.probe_wait_ms);
            if (stop_requested_.load()) { stopConflictListener(); return; }

            bool early_conflict = false;
            for (int i = 0; i < 3; ++i) {
                emitArpProbe(tentative_ll_be, params.flavor);
                if (conflict_detected_.load()) { early_conflict = true; break; }
                if (i < 2) {
                    sleepInterruptible(probe_interval());
                    if (stop_requested_.load()) {
                        stopConflictListener();
                        return;
                    }
                    if (conflict_detected_.load()) {
                        early_conflict = true;
                        break;
                    }
                }
            }
            if (early_conflict) {
                stopConflictListener();
                ++conflict_count;
                if (conflict_count >= static_cast<int>(rfc3927::kMaxConflicts))
                    rate_limit_active = true;
                continue;
            }

            // Continue listening through ANNOUNCE_WAIT. _11/_12/_13
            // explicitly inject conflict in this window per their TC8
            // procedure (Tester reads target_ip from observed Probes,
            // then injects conflict ARP).
            sleepInterruptible(params.announce_wait_ms);
            stopConflictListener();
            if (stop_requested_.load()) return;

            if (conflict_detected_.load()) {
                ++conflict_count;
                if (conflict_count >= static_cast<int>(rfc3927::kMaxConflicts))
                    rate_limit_active = true;
                continue;
            }
            break;  // No conflict — commit this address.
        }

        {
            std::lock_guard<std::mutex> lk(address_mu_);
            committed_address_be_ = tentative_ll_be;
        }

        // Address is now committed. Start the post-claim ARP responder
        // BEFORE the Announce phase: RFC 3927 §2.5 ties defense to
        // "claimed", and a tester probing the LL between Announce 1
        // and Announce 2 (or even immediately after the listener-
        // window exit) MUST receive a Reply. §4.5.6.2 _16 transitions
        // its SCXML on the first Announce, so the tester Request
        // lands ~30 ms after Announce 1 — well before Announce 2 —
        // and the responder must already be polling. Self-emits (the
        // Announces below) are filtered by `sender_hw == dut_mac_`
        // inside the responder.
        cease_requested_.store(false);
        startArpResponder();

        // Phase 2: ANNOUNCE. ANNOUNCE_WAIT was satisfied above (the
        // conflict window covers it), so the first Announce fires
        // immediately; spec ANNOUNCE_WAIT-before-Announce1 wall-time
        // is unchanged from the pre-conflict-listener implementation.
        // Honor cease at the top of each iteration so a conflict that
        // arrives between Announce 1 and Announce 2 (the responder
        // sets cease while we're sleeping `announce_interval_ms`)
        // does not result in Announce 2 emitting with the abandoned
        // LL — RFC 3927 §2.5 says a ceased host has no claim to
        // announce. Currently invisible to §4.5.6.4 SCXML guards
        // (which require is_arp_probe()), but a wire-level deviation
        // worth closing.
        // RFC 3927 §2.4 requires the wire-observable interval between
        // Announce 1 and Announce 2 to equal ANNOUNCE_INTERVAL exactly
        // (TC8 §4.5.6.3 _06 enforces ±50 ms tolerance). The naive
        // `emit; sleep(interval); emit` shape produces wire delta =
        // sleep_duration + sleep_jitter + emit2_latency. Under self-
        // hosted CI workers=4 CPU saturation the sleep_jitter alone
        // exceeds 50 ms — runs 25722823092 / 25631103237 / 25629911035
        // all failed `announce_interval_outside_rfc3927_bounds_with_
        // 50ms_tolerance`. Anchoring Announce 2's emit on an absolute
        // deadline captured BEFORE Announce 1 makes the wire delta =
        // announce_interval_ms + (emit2_latency - emit1_latency); the
        // two emit latencies are symmetric AF_PACKET sendto calls
        // (~50 us each on Linux), so they cancel and the residual is
        // bounded by the final sleep chunk's wake-up jitter alone
        // (<10 ms typical, well within tolerance).
        const auto announce1_anchor = std::chrono::steady_clock::now();
        for (int i = 0; i < 2; ++i) {
            if (cease_requested_.load()) break;
            emitArpAnnounce(tentative_ll_be, params.flavor);
            if (i < 1) {
                const auto announce2_target =
                    announce1_anchor + params.announce_interval_ms;
                const auto sleep_dur = std::chrono::duration_cast<
                    std::chrono::milliseconds>(
                        announce2_target - std::chrono::steady_clock::now());
                if (sleep_dur.count() > 0) sleepInterruptible(sleep_dur);
                if (stop_requested_.load()) {
                    stopArpResponder();
                    return;
                }
            }
        }

        // Steady state: address committed, responder running. Park
        // here until either an external abort (`stop_requested_`) or
        // a defender-cease signal (`cease_requested_`, raised by the
        // responder thread on a conflicting ARP per RFC 3927 §2.5).
        // 50 ms tick matches the responder's poll cadence so the
        // worker reacts to a cease signal within one tick.
        while (!stop_requested_.load() && !cease_requested_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (stop_requested_.load()) return;

        // Cease: tear down the responder + clear the committed
        // address before re-entering Phase 1. The responder must
        // stop BEFORE the address clears so a late-arriving ARP
        // frame between clear and the next responder-start cannot
        // see a stale match. cease_requested_ is reset by the next
        // iteration's `startArpResponder` prelude so a back-to-back
        // cease re-arms cleanly.
        stopArpResponder();
        {
            std::lock_guard<std::mutex> lk(address_mu_);
            committed_address_be_ = 0;
        }
        // continue outer loop — re-enter Phase 1 with a fresh pick.
    }
}

void LinklocalAutoconf::startConflictListener(std::uint32_t tentative_ll_be) {
    stopConflictListener();
    conflict_detected_.store(false);
    stop_listener_.store(false);
    listener_thread_ = std::thread(
        [this, tentative_ll_be]() { runConflictListener(tentative_ll_be); });
}

void LinklocalAutoconf::stopConflictListener() {
    stop_listener_.store(true);
    if (listener_thread_.joinable()) {
        listener_thread_.join();
    }
}

void LinklocalAutoconf::runConflictListener(std::uint32_t tentative_ll_be) {
    int sk = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sk < 0) return;

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface_.c_str(), IFNAMSIZ - 1);
    if (::ioctl(sk, SIOCGIFINDEX, &ifr) < 0) {
        ::close(sk);
        return;
    }

    sockaddr_ll bind_addr{};
    bind_addr.sll_family   = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ARP);
    bind_addr.sll_ifindex  = ifr.ifr_ifindex;
    if (::bind(sk, reinterpret_cast<sockaddr*>(&bind_addr),
               sizeof(bind_addr)) < 0) {
        ::close(sk);
        return;
    }

    while (!stop_listener_.load() && !stop_requested_.load()) {
        pollfd pfd{};
        pfd.fd     = sk;
        pfd.events = POLLIN;
        const int rc = ::poll(&pfd, 1, 50);  // 50 ms tick
        if (rc <= 0) continue;
        if ((pfd.revents & POLLIN) == 0) continue;

        std::uint8_t buf[64];
        const ssize_t n = ::recv(sk, buf, sizeof(buf), 0);
        // 14 B Ethernet header + 28 B Eth/IPv4 ARP body. Anything
        // shorter is malformed.
        if (n < 42) continue;
        const std::uint8_t* arp = buf + 14;
        const std::uint16_t opcode =
            static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(arp[6]) << 8) |
                static_cast<std::uint16_t>(arp[7]));
        std::array<std::uint8_t, 6> sender_hw{};
        std::memcpy(sender_hw.data(), arp + 8, 6);
        std::uint32_t sender_ip_be = 0;
        std::memcpy(&sender_ip_be, arp + 14, 4);
        std::uint32_t target_ip_be = 0;
        std::memcpy(&target_ip_be, arp + 24, 4);

        // Drop our own emits — AF_PACKET SOCK_RAW reflects every
        // outbound frame back to all listeners on the same iface.
        if (sender_hw == dut_mac_) continue;

        // RFC 3927 §2.2.1 conflict predicates:
        //   (a) any ARP (Request OR Reply) with sender_proto_ip ==
        //       tentative_ll. Covers _11 (Request) and _12 (Reply).
        //   (b) ARP Probe (opcode=1, sender_proto_ip=0) with target
        //       == tentative_ll AND sender_hw != dut_mac. The dut_mac
        //       check is already handled by the early-out above so
        //       no separate guard. Covers _13.
        const bool sender_match = (sender_ip_be == tentative_ll_be);
        const bool target_probe_match =
            (opcode == 1 && sender_ip_be == 0 &&
             target_ip_be == tentative_ll_be);
        if (sender_match || target_probe_match) {
            conflict_detected_.store(true);
            break;
        }
    }
    ::close(sk);
}

void LinklocalAutoconf::startArpResponder() {
    stopArpResponder();
    stop_responder_.store(false);
    responder_ready_.store(false);
    responder_thread_ = std::thread([this]() { runArpResponder(); });
    // Block until the responder has bound its AF_PACKET socket so the
    // very first tester ARP Request after Phase 2 commit cannot race
    // the bind. 500 ms is generous: a healthy iface binds in <1 ms;
    // anything beyond that points at a broken iface and the responder
    // would never function anyway. Worst case (timeout) the caller
    // proceeds without a bound responder — same pre-fix behaviour, so
    // no regression vs prior session even on a degenerate host.
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(500);
    while (!responder_ready_.load() &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
}

void LinklocalAutoconf::stopArpResponder() {
    stop_responder_.store(true);
    if (responder_thread_.joinable()) {
        responder_thread_.join();
    }
}

void LinklocalAutoconf::runArpResponder() {
    int sk = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sk < 0) return;

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface_.c_str(), IFNAMSIZ - 1);
    if (::ioctl(sk, SIOCGIFINDEX, &ifr) < 0) {
        ::close(sk);
        return;
    }

    sockaddr_ll bind_addr{};
    bind_addr.sll_family   = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ARP);
    bind_addr.sll_ifindex  = ifr.ifr_ifindex;
    if (::bind(sk, reinterpret_cast<sockaddr*>(&bind_addr),
               sizeof(bind_addr)) < 0) {
        ::close(sk);
        return;
    }

    // Signal to startArpResponder that the AF_PACKET socket is bound
    // and the kernel has begun delivering frames into our recv queue.
    // From this point any ARP Request on the iface will be observed.
    responder_ready_.store(true);

    while (!stop_responder_.load() && !stop_requested_.load()) {
        pollfd pfd{};
        pfd.fd     = sk;
        pfd.events = POLLIN;
        const int rc = ::poll(&pfd, 1, 50);  // 50 ms tick
        if (rc <= 0) continue;
        if ((pfd.revents & POLLIN) == 0) continue;

        std::uint8_t buf[64];
        const ssize_t n = ::recv(sk, buf, sizeof(buf), 0);
        if (n < 42) continue;
        const std::uint8_t* arp = buf + 14;
        const std::uint16_t opcode =
            static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(arp[6]) << 8) |
                static_cast<std::uint16_t>(arp[7]));
        std::array<std::uint8_t, 6> sender_hw{};
        std::memcpy(sender_hw.data(), arp + 8, 6);
        std::uint32_t sender_ip_be = 0;
        std::memcpy(&sender_ip_be, arp + 14, 4);
        std::uint32_t target_ip_be = 0;
        std::memcpy(&target_ip_be, arp + 24, 4);

        // Drop our own emits — AF_PACKET reflects every TX back to
        // every listener bound to ETH_P_ARP on the same iface.
        if (sender_hw == dut_mac_) continue;

        // Snapshot the committed address under the mutex so abort()'s
        // post-join clear (which sets committed_address_be_ = 0)
        // cannot race a stale match here.
        std::uint32_t committed_be = 0;
        {
            std::lock_guard<std::mutex> lk(address_mu_);
            committed_be = committed_address_be_;
        }
        if (committed_be == 0) continue;

        // Conflict path takes precedence. RFC 3927 §2.5: any ARP
        // packet (Request OR Reply) whose sender_proto_ip matches our
        // committed LL but whose sender_hw is not ours indicates an
        // address conflict. The self-emit early-out above already
        // filters our own TX, so a sender_proto_ip match here is
        // unconditionally third-party. Method 1 ("configure a new
        // address"): set the cease signal and let the worker thread
        // tear down the claim. §4.5.6.4 CONFLICT_06..10 verify this.
        if (sender_ip_be == committed_be) {
            cease_requested_.store(true);
            continue;
        }

        // Reply path. RFC 3927 §2.5: an ARP Request whose target is
        // our claimed LL deserves a Reply identifying our hardware
        // address. §4.5.6.2 _16 + §4.5.6.4 CONFLICT_11 verify this.
        if (opcode != 1) continue;
        if (target_ip_be != committed_be) continue;

        emitArpReply(sender_ip_be, sender_hw, flavor_);
    }
    ::close(sk);
}

void LinklocalAutoconf::emitArpReply(
    std::uint32_t target_ip_be,
    const std::array<std::uint8_t, 6>& target_hw,
    LinklocalAutoconfFlavor flavor) {
    std::uint32_t sender_ip_be = 0;
    {
        std::lock_guard<std::mutex> lk(address_mu_);
        sender_ip_be = committed_address_be_;
    }
    if (sender_ip_be == 0) return;

    // Compliant defending-Reply shape per RFC 3927 §2.5. `flavor`
    // mutates exactly one field (and only one): Reply-shape flavors
    // are active here, every Probe/Announce flavor is a passive
    // `break` so -Wswitch forces all-three-builder consideration.
    std::array<std::uint8_t, 6> eth_dst = kEthBroadcast;
    switch (flavor) {
        case LinklocalAutoconfFlavor::None:
        // Probe- and Announce-phase flavors: the defending Reply stays
        // compliant.
        case LinklocalAutoconfFlavor::SenderIpNonzero:
        case LinklocalAutoconfFlavor::TargetOutsidePrefix:
        case LinklocalAutoconfFlavor::TargetInReservedRange:
        case LinklocalAutoconfFlavor::TargetHwNonzero:
        case LinklocalAutoconfFlavor::SenderHwWrong:
        case LinklocalAutoconfFlavor::ProbeEthDstUnicast:
        case LinklocalAutoconfFlavor::AnnounceEthDstUnicast:
        case LinklocalAutoconfFlavor::AnnounceSenderTargetMismatch:
        case LinklocalAutoconfFlavor::AnnounceSenderHwWrong:
        case LinklocalAutoconfFlavor::AnnounceTargetHwNonzero:
            break;
        case LinklocalAutoconfFlavor::ReplySenderIpWrong:
            // RFC 3927 §2.5: the defending Reply's sender_proto_ip MUST
            // be the committed LL. Drive it to the DUT iface IP (a
            // routable, non-LL value distinguishable on capture).
            sender_ip_be = dut_iface_ip_be_;
            break;
        case LinklocalAutoconfFlavor::ReplyEthDstUnicast:
            // RFC 3927 §2.5 last MUST: a Reply whose sender_proto_ip is
            // in 169.254/16 MUST be broadcast. Direct the Ethernet dst
            // at the asker's MAC (the RFC 826 default unicast a
            // non-conformant DUT might emit).
            eth_dst = target_hw;
            break;
    }

    // 14 B Ethernet + 28 B ARP. RFC 3927 §2.5 last MUST: any ARP
    // packet whose sender_proto_ip is in 169.254/16 — including
    // Replies — is sent via link-layer broadcast, not unicast. Our
    // sender_proto_ip is `committed_address_be_` (always in
    // 169.254/16 by Phase 1 construction), so eth_dst = broadcast
    // is unconditional. RFC 826 ARP Reply target_hw = asker's MAC
    // is unchanged (the L3-level reply identity is independent of
    // L2 framing).
    std::uint8_t f[42] = {};
    std::memcpy(f + 0, eth_dst.data(), 6);          // Eth dst (broadcast; flavor mutates)
    std::memcpy(f + 6, dut_mac_.data(), 6);         // Eth src = DUT
    writeBe16(f + 12, kEthTypeArp);

    writeBe16(f + 14, 0x0001);                       // hw_type = Ethernet
    writeBe16(f + 16, kEthTypeIp4);                  // proto_type = IPv4
    f[18] = 6;                                        // hw_addr_len
    f[19] = 4;                                        // proto_addr_len
    writeBe16(f + 20, 0x0002);                       // opcode = Reply
    std::memcpy(f + 22, dut_mac_.data(), 6);         // sender_hw
    std::memcpy(f + 28, &sender_ip_be, 4);           // sender_proto_ip = LL
    std::memcpy(f + 32, target_hw.data(), 6);        // target_hw
    std::memcpy(f + 38, &target_ip_be, 4);           // target_proto_ip

    sendRaw(f, sizeof(f));
}

}  // namespace tc8::dut
