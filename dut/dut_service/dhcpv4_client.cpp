#include "dhcpv4_client.h"

#include "wire/ip_checksum.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
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

constexpr std::array<std::uint8_t, 6> kEthZero{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

constexpr std::array<std::uint8_t, 6> kEthBroadcast{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

constexpr std::uint8_t kBootRequest = 1;
constexpr std::uint8_t kBootReply   = 2;

constexpr std::uint8_t kDhcpDiscover = 1;
constexpr std::uint8_t kDhcpRequest  = 3;
constexpr std::uint8_t kDhcpDecline  = 4;

constexpr std::size_t kBootpFixedLen = 240;  // op..options-magic
constexpr std::uint16_t kUdpClientPort = 68;
constexpr std::uint16_t kUdpServerPort = 67;

// §4.7.6.5 PARAMETERS_04 / RFC 2132 §9.8: clients MAY include Option 55
// (Parameter Request List) in DISCOVER, and MUST repeat the same list in
// any subsequent REQUEST. The four codes match what every common DHCP
// client (dhclient, systemd-networkd, busybox-udhcpc) requests by default.
constexpr std::array<std::uint8_t, 4> kParameterRequestList{
    1,    // Subnet Mask
    3,    // Router
    6,    // Domain Name Server
    15,   // Domain Name
};

using ::tc8::wire::inetChecksum;
using ::tc8::wire::udpChecksum;
using ::tc8::wire::writeBe16;

// Bounded-jitter abort-aware sleep used by both restart pivots:
//   * post-NAK / lease-expiry — RFC 2131 §4.4.1 SHOULD ([1, 10] s,
//     §4.7.6.9 INIT_ALLOC_01).
//   * post-DECLINE — RFC 2131 §3.1 SHOULD ([10, ∞) s, §4.7.6.3
//     ALLOCATING_08).
// Negative `min_ms` is clamped to 0; `max_ms < min_ms` is clamped up
// to `min_ms` (degenerate window collapses to a fixed wait). Polls
// `stop` at 50 ms slices so abort() latency stays bounded — same
// idiom used by the BOUND-phase tick.
void drawAndSleepRandomMs(std::mt19937&            rng,
                          const std::atomic<bool>& stop,
                          std::int64_t             min_ms,
                          std::int64_t             max_ms) {
    const auto lo = static_cast<std::uint32_t>(min_ms < 0 ? 0 : min_ms);
    const auto hi = static_cast<std::uint32_t>(max_ms < lo ? lo : max_ms);
    std::uniform_int_distribution<std::uint32_t> wait_dist(lo, hi);
    const std::uint32_t wait_ms = wait_dist(rng);
    const auto wait_end = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(wait_ms);
    while (!stop.load() &&
           std::chrono::steady_clock::now() < wait_end) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

// Walk the DHCP options TLV chain (RFC 2132 §9.6) starting just past
// the magic cookie. Returns the value of `code` if present (writing
// into out_value up to *out_len bytes; *out_len updated), or false on
// absence / malformed length / END.
bool findDhcpOption(const std::uint8_t* opts, std::size_t opts_len,
                    std::uint8_t code,
                    std::uint8_t* out_value, std::size_t* out_len) {
    std::size_t i = 0;
    while (i < opts_len) {
        const std::uint8_t c = opts[i];
        if (c == 0xFF) return false;        // END
        if (c == 0x00) { ++i; continue; }   // PAD
        if (i + 1 >= opts_len) return false;
        const std::uint8_t l = opts[i + 1];
        if (i + 2 + l > opts_len) return false;
        if (c == code) {
            const std::size_t copy_len = std::min<std::size_t>(*out_len, l);
            std::memcpy(out_value, opts + i + 2, copy_len);
            *out_len = copy_len;
            return true;
        }
        i += 2 + l;
    }
    return false;
}

}  // namespace

Dhcpv4Client::Dhcpv4Client() = default;

Dhcpv4Client::~Dhcpv4Client() {
    abort();
}

void Dhcpv4Client::bind(std::string iface,
                         std::array<std::uint8_t, 6> dut_mac) {
    iface_   = std::move(iface);
    dut_mac_ = dut_mac;
}

bool Dhcpv4Client::start(const Params& params) {
    abort();
    stop_requested_.store(false);
    worker_ = std::thread([this, params]() { runLoop(params); });
    return true;
}

void Dhcpv4Client::abort() {
    stop_requested_.store(true);
    if (worker_.joinable()) {
        worker_.join();
    }
    std::uint32_t to_remove = 0;
    {
        std::lock_guard<std::mutex> lk(lease_mu_);
        committed_lease_be_  = 0;
        to_remove            = installed_router_be_;
        installed_router_be_ = 0;
    }
    // §4.7.6.7 CM_05/_06 cleanup: remove the default route the worker
    // installed on BOUND so per-case netns scope is preserved (the
    // smoke-test runs each case in its own netns, but tests that
    // share the netns across iterations rely on this for isolation).
    if (to_remove != 0U) {
        removeDefaultRoute(to_remove);
    }
}

std::uint32_t Dhcpv4Client::currentLeaseBe() const {
    std::lock_guard<std::mutex> lk(lease_mu_);
    return committed_lease_be_;
}

// Set up an `rtentry` describing a default route (`0.0.0.0/0 via gw`)
// on the bound iface. Caller fills `dev_buf` with `iface_.c_str()` and
// passes both so the route's `rt_dev` can point at stable storage that
// outlives this helper's stack frame.
namespace {

void fillDefaultRouteEntry(rtentry& rt, char* dev_buf,
                            std::uint32_t gateway_be) {
    std::memset(&rt, 0, sizeof(rt));
    auto* dst = reinterpret_cast<sockaddr_in*>(&rt.rt_dst);
    dst->sin_family      = AF_INET;
    dst->sin_addr.s_addr = 0;  // 0.0.0.0 → default route

    auto* mask = reinterpret_cast<sockaddr_in*>(&rt.rt_genmask);
    mask->sin_family      = AF_INET;
    mask->sin_addr.s_addr = 0;  // 0.0.0.0 → default route

    auto* gw = reinterpret_cast<sockaddr_in*>(&rt.rt_gateway);
    gw->sin_family      = AF_INET;
    gw->sin_addr.s_addr = gateway_be;

    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    rt.rt_dev   = dev_buf;
}

}  // namespace

int Dhcpv4Client::installDefaultRoute(std::uint32_t gateway_be) {
    if (gateway_be == 0U || iface_.empty()) return -1;

    int sk = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sk < 0) return -1;

    rtentry rt{};
    char    dev_buf[IFNAMSIZ] = {};
    std::strncpy(dev_buf, iface_.c_str(), IFNAMSIZ - 1);
    fillDefaultRouteEntry(rt, dev_buf, gateway_be);

    int rc = ::ioctl(sk, SIOCADDRT, &rt);
    if (rc < 0 && errno == EEXIST) {
        // Same default gateway already installed (e.g. fresh BOUND
        // after a NAK-then-rebound on the same lease). Treat as
        // success — the post-condition (route reachable) holds.
        rc = 0;
    } else if (rc < 0) {
        std::fprintf(stderr,
                     "dhcpv4: SIOCADDRT default via 0x%08x dev %s failed: %s\n",
                     ::ntohl(gateway_be), iface_.c_str(),
                     std::strerror(errno));
    }
    ::close(sk);
    return rc;
}

int Dhcpv4Client::removeDefaultRoute(std::uint32_t gateway_be) {
    if (gateway_be == 0U || iface_.empty()) return -1;

    int sk = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sk < 0) return -1;

    rtentry rt{};
    char    dev_buf[IFNAMSIZ] = {};
    std::strncpy(dev_buf, iface_.c_str(), IFNAMSIZ - 1);
    fillDefaultRouteEntry(rt, dev_buf, gateway_be);

    int rc = ::ioctl(sk, SIOCDELRT, &rt);
    // ESRCH (no such route) is not an error from the harness's
    // perspective — the abort path runs even when no route was
    // installed, so a missing route is the steady-state fast path.
    if (rc < 0 && errno != ESRCH) {
        std::fprintf(stderr,
                     "dhcpv4: SIOCDELRT default via 0x%08x dev %s failed: %s\n",
                     ::ntohl(gateway_be), iface_.c_str(),
                     std::strerror(errno));
    }
    ::close(sk);
    return rc;
}

int Dhcpv4Client::sendRaw(const std::uint8_t* frame, std::size_t len) {
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
    std::memcpy(dest.sll_addr, frame, 6);
    ssize_t rc = ::sendto(sk, frame, len, 0,
                          reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    ::close(sk);
    return rc < 0 ? -3 : 0;
}

void Dhcpv4Client::emitDhcpMessage(const DhcpEmitSpec& spec) {
    // §4.7 Phase F fault injection — decoded FIRST because force-including
    // an otherwise-omitted option (RENEWING/REBINDING leak mutants) grows
    // the options length, which the opts_len math below must see. Each
    // flavor mutates exactly one DUT-emitted field so the matching §4.7
    // _neg case's guard (dead against a conformant client) becomes
    // reachable. switch-no-default: -Werror=switch forces every future
    // flavor to declare its emit-side disposition here. None and the
    // post-BOUND LeakLinkLocalAfterBind flavor leave the wire conformant.
    //
    // Effective field values start from the spec and are overridden per
    // flavor; the option-include + length math reads the effective
    // requested_addr_be / server_id_be so a forced option grows opts_len.
    std::uint32_t l3_src_be         = spec.l3_src_be;
    std::uint32_t l3_dst_be         = spec.l3_dst_be;
    std::uint32_t ciaddr_be         = spec.ciaddr_be;
    std::uint32_t requested_addr_be = spec.requested_addr_be;
    std::uint32_t server_id_be      = spec.server_id_be;
    bool corrupt_magic_cookie       = false;
    bool omit_message_type_option   = false;
    bool set_reserved_flag_bit      = false;
    bool drop_end_option            = false;

    // Lifecycle phase, derived from the ORIGINAL spec (before mutation) so
    // a flavor that rewrites ciaddr/dst cannot perturb the detection:
    //   SELECTING REQUEST : ciaddr == 0
    //   RENEWING  REQUEST : ciaddr != 0, dst != broadcast (unicast to server)
    //   REBINDING REQUEST : ciaddr != 0, dst == broadcast
    // SELECTING mutants gate on `is_request` (the preceding DISCOVER stays
    // conformant so the OFFER matches); RENEWING/REBINDING mutants gate on
    // `is_reacq` (DISCOVER + SELECTING REQUEST stay conformant so the
    // lifecycle reaches BOUND and the reacquisition REQUEST under test).
    constexpr std::uint32_t kBroadcastBe = 0xFFFFFFFFU;
    const bool is_request  = (spec.msg_type == kDhcpRequest);
    const bool is_reacq    = is_request && spec.ciaddr_be != 0U;
    const bool is_renewing = is_reacq && spec.l3_dst_be != kBroadcastBe;
    // §4.7 sentinel mutation values (RFC 5737 TEST-NET-1, visibly wrong).
    constexpr std::uint32_t kSentinelDst    = 192U | (2U << 16) | (1U  << 24);  // 192.0.2.1
    constexpr std::uint32_t kSentinelSrc    = 192U | (2U << 16) | (2U  << 24);  // 192.0.2.2
    constexpr std::uint32_t kSentinelOpt50  = 192U | (2U << 16) | (50U << 24);  // 192.0.2.50
    constexpr std::uint32_t kSentinelOpt54  = 192U | (2U << 16) | (54U << 24);  // 192.0.2.54
    constexpr std::uint32_t kSentinelCiaddr = 192U | (2U << 16) | (11U << 24);  // 192.0.2.11
    constexpr std::uint32_t kSentinelRenDst = 192U | (2U << 16) | (9U  << 24);  // 192.0.2.9
    switch (flavor_) {
        case Dhcpv4ClientFlavor::None:
        case Dhcpv4ClientFlavor::LeakLinkLocalAfterBind:
            break;  // conformant emit (leak acts post-BOUND, not here)
        case Dhcpv4ClientFlavor::DiscoverMagicCookieCorrupt:
            corrupt_magic_cookie = true;
            break;
        case Dhcpv4ClientFlavor::DiscoverOmitMessageType:
            omit_message_type_option = true;
            break;
        case Dhcpv4ClientFlavor::DiscoverReservedFlagsSet:
            set_reserved_flag_bit = true;
            break;
        case Dhcpv4ClientFlavor::DiscoverDstUnicast:
            l3_dst_be = kSentinelDst;  // not the limited broadcast
            break;
        case Dhcpv4ClientFlavor::DiscoverSrcNonzero:
            l3_src_be = kSentinelSrc;  // non-zero pre-bind src
            break;
        case Dhcpv4ClientFlavor::DiscoverDropEnd:
            drop_end_option = true;
            break;
        case Dhcpv4ClientFlavor::RequestSrcNonzero:
            // §4.7.6.7 CM_04: non-zero source on the SELECTING REQUEST.
            if (is_request) l3_src_be = kSentinelSrc;
            break;
        case Dhcpv4ClientFlavor::RequestDstUnicast:
            // §4.7.6.3 ALLOCATING_05: unicast the SELECTING REQUEST.
            if (is_request) l3_dst_be = kSentinelDst;
            break;
        case Dhcpv4ClientFlavor::RequestCiaddrNonzero:
            // §4.7.6.8 REQUEST_01: fill ciaddr (RFC 2131 §4.3.2 -> 0).
            if (is_request) ciaddr_be = spec.requested_addr_be;
            break;
        case Dhcpv4ClientFlavor::RequestServerIdCorrupt:
            // §4.7.6.3 ALLOCATING_03: wrong Option 54 server-id echo.
            if (is_request) server_id_be = kSentinelOpt54;
            break;
        case Dhcpv4ClientFlavor::RequestRequestedIpCorrupt:
            // §4.7.6.8 REQUEST_02: wrong Option 50 requested-IP echo.
            if (is_request) requested_addr_be = kSentinelOpt50;
            break;
        case Dhcpv4ClientFlavor::ReacqRequestIncludeServerId:
            // §4.7.6.8 REQUEST_06/_09: RENEWING/REBINDING REQUEST MUST NOT
            // carry Option 54 (RFC 2131 §4.3.6 table 5). Force-include it
            // (server_id_be was 0 -> opt54 omitted on the conformant path).
            if (is_reacq) server_id_be = kSentinelOpt54;
            break;
        case Dhcpv4ClientFlavor::ReacqRequestIncludeRequestedIp:
            // §4.7.6.8 REQUEST_07/_10: reacquisition REQUEST MUST NOT carry
            // Option 50. Force-include it.
            if (is_reacq) requested_addr_be = kSentinelOpt50;
            break;
        case Dhcpv4ClientFlavor::ReacqRequestCiaddrWrong:
            // §4.7.6.8 REQUEST_08/_11: reacquisition ciaddr MUST equal the
            // bound IP; write a wrong address.
            if (is_reacq) ciaddr_be = kSentinelCiaddr;
            break;
        case Dhcpv4ClientFlavor::RenewingRequestDstWrong:
            // §4.7.6.7 CM_02 / §4.7.6.8 REACQUISITION_01: the RENEWING
            // REQUEST MUST be unicast to the server-id; send it elsewhere.
            if (is_renewing) l3_dst_be = kSentinelRenDst;
            break;
    }

    // Options layout (in spec order, with conditional inclusion):
    //   Option 53 (Message Type)        always           — 3 B
    //   Option 50 (Requested IP)        requested_addr  — 6 B (4 B value + 2 B TLV header)
    //   Option 54 (Server Identifier)   server_id       — 6 B
    //   Option 55 (Parameter Request)   always           — 2 + N B
    //   END (0xFF)                      always           — 1 B
    const bool include_opt50 = (requested_addr_be != 0U);
    const bool include_opt54 = (server_id_be != 0U);
    const std::size_t opts_len =
        3 +
        (include_opt50 ? 6 : 0) +
        (include_opt54 ? 6 : 0) +
        (2 + kParameterRequestList.size()) +
        1;
    const std::size_t dhcp_body_len = kBootpFixedLen + opts_len;
    const std::size_t udp_len       = 8 + dhcp_body_len;
    const std::size_t ip4_len       = 20 + udp_len;
    const std::size_t frame_len     = 14 + ip4_len;

    std::uint8_t f[14 + 20 + 8 + 300] = {};
    if (frame_len > sizeof(f)) {
        // Defensive: every spec the client emits today fits comfortably,
        // but a future caller adding more Option-bearing TLVs without
        // resizing the buffer would silently corrupt the stack. Bail
        // before that happens.
        return;
    }

    std::memcpy(f + 0, kEthBroadcast.data(), 6);
    std::memcpy(f + 6, dut_mac_.data(), 6);
    writeBe16(f + 12, kEthTypeIp4);

    std::uint8_t* ip = f + 14;
    ip[0] = 0x45;
    ip[1] = 0x00;
    writeBe16(ip + 2, static_cast<std::uint16_t>(ip4_len));
    writeBe16(ip + 4, 0x0000);
    writeBe16(ip + 6, 0x0000);
    ip[8] = 64;
    ip[9] = 0x11;
    writeBe16(ip + 10, 0);
    std::memcpy(ip + 12, &l3_src_be, 4);
    std::memcpy(ip + 16, &l3_dst_be, 4);
    writeBe16(ip + 10, inetChecksum(ip, 20));

    std::uint8_t* udp = ip + 20;
    writeBe16(udp + 0, kUdpClientPort);
    writeBe16(udp + 2, kUdpServerPort);
    writeBe16(udp + 4, static_cast<std::uint16_t>(udp_len));
    writeBe16(udp + 6, 0);

    std::uint8_t* bp = udp + 8;
    bp[0] = kBootRequest;
    bp[1] = 1;       // htype = Ethernet
    bp[2] = 6;       // hlen
    bp[3] = 0;       // hops
    std::memcpy(bp + 4, &spec.xid_be, 4);
    // ciaddr per RFC 2131 §4.3.2 (zero in SELECTING) / §4.4.5 (filled
    // with bound IP in RENEWING/REBINDING). Other BOOTP address fields
    // (yiaddr/siaddr/giaddr) stay zero.
    std::memcpy(bp + 12, &ciaddr_be, 4);
    std::memcpy(bp + 28, dut_mac_.data(), 6);
    if (set_reserved_flag_bit) {
        // §4.7.6.1 SUMMARY_04: set 'flags' reserved bit 1 (the BROADCAST
        // flag is bit 0; bits 1..15 MUST be zero per RFC 2131 §2).
        // bp[10]/bp[11] are zero by buffer init on the conformant path.
        bp[11] = 0x02;
    }
    bp[236] = 0x63;
    bp[237] = 0x82;
    bp[238] = 0x53;
    bp[239] = 0x63;
    if (corrupt_magic_cookie) {
        // §4.7.6.2 PROTOCOL_01: zero the first cookie byte so the
        // captured frame's magic_cookie_valid predicate is false.
        bp[236] = 0x00;
    }

    std::uint8_t* opts = bp + 240;
    std::size_t i = 0;

    // Option 53 (DHCP Message Type)
    if (omit_message_type_option) {
        // §4.7.6.2 PROTOCOL_02: emit NO Option 53 — three PAD bytes
        // occupy the slot so option offsets and the IP/UDP length fields
        // stay valid; the message simply lacks the mandatory DHCP Message
        // Type option (the options walk skips PAD and never sets
        // message_type_option_present).
        opts[i++] = 0x00;
        opts[i++] = 0x00;
        opts[i++] = 0x00;
    } else {
        opts[i++] = 53;
        opts[i++] = 1;
        opts[i++] = spec.msg_type;
    }

    if (include_opt50) {
        // Option 50 (Requested IP Address). Value is the effective
        // requested_addr_be — the offered IP on the conformant path, or a
        // sentinel under the §4.7.6.8 REQUEST_02 corrupt / REQUEST_07/_10
        // force-include mutants.
        opts[i++] = 50;
        opts[i++] = 4;
        std::memcpy(opts + i, &requested_addr_be, 4);
        i += 4;
    }
    if (include_opt54) {
        // Option 54 (Server Identifier). Value is the effective
        // server_id_be — the OFFER server-id on the conformant path, or a
        // sentinel under the §4.7.6.3 ALLOCATING_03 corrupt / REQUEST_06/_09
        // force-include mutants.
        opts[i++] = 54;
        opts[i++] = 4;
        std::memcpy(opts + i, &server_id_be, 4);
        i += 4;
    }

    // Option 55 (Parameter Request List) — RFC 2131 §4.3.6 table 5
    // permits the echo in every BOOTREQUEST and §4.7.6.5 PARAMETERS_04
    // verifies it.
    opts[i++] = 55;
    opts[i++] = static_cast<std::uint8_t>(kParameterRequestList.size());
    std::memcpy(opts + i, kParameterRequestList.data(),
                kParameterRequestList.size());
    i += kParameterRequestList.size();

    // §4.7.6.7 CONSTRUCTING_MESSAGES_01: under DropEnd the END (0xFF) is
    // replaced by a PAD (0x00) so the options walk runs off the blob
    // without seeing END → last_option_is_end is false.
    opts[i++] = drop_end_option ? 0x00 : 0xFF;  // END (PAD if mutated)

    writeBe16(udp + 6, udpChecksum(l3_src_be, l3_dst_be, udp, udp_len));
    sendRaw(f, frame_len);
}

void Dhcpv4Client::emitDhcpDiscover(std::uint32_t xid_be) {
    emitDhcpMessage(DhcpEmitSpec{
        /*msg_type=*/         kDhcpDiscover,
        /*xid_be=*/           xid_be,
        /*l3_src_be=*/        0x00000000U,
        /*l3_dst_be=*/        0xFFFFFFFFU,
        /*ciaddr_be=*/        0U,
        /*requested_addr_be=*/0U,
        /*server_id_be=*/     0U,
    });
}

void Dhcpv4Client::emitDhcpRequest(std::uint32_t xid_be,
                                    std::uint32_t requested_addr_be,
                                    std::uint32_t server_id_be) {
    // RFC 2131 §4.3.2 / §4.4.1 SELECTING REQUEST: broadcast with src=0
    // (the client has not yet bound the offered address). Option 50
    // carries the requested IP; Option 54 echoes the chosen server.
    emitDhcpMessage(DhcpEmitSpec{
        /*msg_type=*/         kDhcpRequest,
        /*xid_be=*/           xid_be,
        /*l3_src_be=*/        0x00000000U,
        /*l3_dst_be=*/        0xFFFFFFFFU,
        /*ciaddr_be=*/        0U,
        /*requested_addr_be=*/requested_addr_be,
        /*server_id_be=*/     server_id_be,
    });
}

void Dhcpv4Client::emitDhcpRequestRenewing(std::uint32_t xid_be,
                                            std::uint32_t client_addr_be,
                                            std::uint32_t server_id_be) {
    // RFC 2131 §4.4.5 RENEWING: IP-unicast REQUEST to the server. Options
    // table 5 forbids Option 50 + Option 54; ciaddr carries the bound IP.
    // Encoded by the spec's `requested_addr_be` / `server_id_be` zero
    // sentinels which suppress those options inside `emitDhcpMessage`.
    emitDhcpMessage(DhcpEmitSpec{
        /*msg_type=*/         kDhcpRequest,
        /*xid_be=*/           xid_be,
        /*l3_src_be=*/        client_addr_be,
        /*l3_dst_be=*/        server_id_be,
        /*ciaddr_be=*/        client_addr_be,
        /*requested_addr_be=*/0U,
        /*server_id_be=*/     0U,
    });
}

void Dhcpv4Client::emitDhcpRequestRebinding(std::uint32_t xid_be,
                                             std::uint32_t client_addr_be) {
    // RFC 2131 §4.4.5 REBINDING: broadcast variant of the RENEWING
    // REQUEST after the unicast attempt fails. Same option constraints.
    emitDhcpMessage(DhcpEmitSpec{
        /*msg_type=*/         kDhcpRequest,
        /*xid_be=*/           xid_be,
        /*l3_src_be=*/        client_addr_be,
        /*l3_dst_be=*/        0xFFFFFFFFU,
        /*ciaddr_be=*/        client_addr_be,
        /*requested_addr_be=*/0U,
        /*server_id_be=*/     0U,
    });
}

void Dhcpv4Client::emitDhcpDecline(std::uint32_t xid_be,
                                    std::uint32_t declined_addr_be,
                                    std::uint32_t server_id_be) {
    // RFC 2131 §4.4.4: DHCPDECLINE wire envelope mirrors DISCOVER —
    // src=0, dst=255.255.255.255, ciaddr=0 — with msg_type=4 and the
    // declined IP carried in Option 50 + the originating server in
    // Option 54.
    emitDhcpMessage(DhcpEmitSpec{
        /*msg_type=*/         kDhcpDecline,
        /*xid_be=*/           xid_be,
        /*l3_src_be=*/        0x00000000U,
        /*l3_dst_be=*/        0xFFFFFFFFU,
        /*ciaddr_be=*/        0U,
        /*requested_addr_be=*/declined_addr_be,
        /*server_id_be=*/     server_id_be,
    });
}

void Dhcpv4Client::emitArpProbe(std::uint32_t target_ip_be) {
    // RFC 2131 §4.4.1 / RFC 5227 §2.1.1 ARP Probe:
    //   sender_hw    = DUT MAC
    //   sender_ip    = 0.0.0.0
    //   target_hw    = 00:00:00:00:00:00
    //   target_ip    = address being probed (the OFFER yiaddr)
    //   eth_dst      = ff:ff:ff:ff:ff:ff (broadcast)
    //   opcode       = 1 (Request)
    std::uint8_t f[42] = {};
    std::memcpy(f + 0, kEthBroadcast.data(), 6);
    std::memcpy(f + 6, dut_mac_.data(), 6);
    writeBe16(f + 12, kEthTypeArp);

    writeBe16(f + 14, 0x0001);            // hw_type = Ethernet
    writeBe16(f + 16, kEthTypeIp4);       // proto_type = IPv4
    f[18] = 6;                             // hw_addr_len
    f[19] = 4;                             // proto_addr_len
    writeBe16(f + 20, 0x0001);            // opcode = Request

    std::memcpy(f + 22, dut_mac_.data(), 6);
    const std::uint32_t sender_ip_be = 0;
    std::memcpy(f + 28, &sender_ip_be, 4);
    std::memcpy(f + 32, kEthZero.data(), 6);
    std::memcpy(f + 38, &target_ip_be, 4);

    sendRaw(f, sizeof(f));
}

void Dhcpv4Client::emitArpAnnounce(std::uint32_t committed_ip_be) {
    // RFC 2131 §4.4.1 SHOULD broadcast ARP Reply announcing the bound
    // IP — clears stale ARP caches on the link. opcode=2,
    // sender_hw == target_hw == DUT MAC; sender_ip == target_ip ==
    // committed IP; eth_dst broadcast.
    std::uint8_t f[42] = {};
    std::memcpy(f + 0, kEthBroadcast.data(), 6);
    std::memcpy(f + 6, dut_mac_.data(), 6);
    writeBe16(f + 12, kEthTypeArp);

    writeBe16(f + 14, 0x0001);
    writeBe16(f + 16, kEthTypeIp4);
    f[18] = 6;
    f[19] = 4;
    writeBe16(f + 20, 0x0002);            // opcode = Reply

    std::memcpy(f + 22, dut_mac_.data(), 6);
    std::memcpy(f + 28, &committed_ip_be, 4);
    std::memcpy(f + 32, dut_mac_.data(), 6);
    std::memcpy(f + 38, &committed_ip_be, 4);

    sendRaw(f, sizeof(f));
}

bool Dhcpv4Client::runArpProbeListener(std::uint32_t              probed_ip_be,
                                        std::chrono::milliseconds  listen) {
    // §4.7.6.9 INIT_ALLOC_09 conflict detector. Open AF_PACKET
    // SOCK_RAW(ETH_P_ARP) on the bound iface, poll for `listen` ms,
    // and treat any ARP frame whose `sender_proto_ip` equals
    // `probed_ip_be` from a non-DUT hardware address as the RFC 2131
    // §4.4.1 "address appears to be in use" signal.
    int sk = ::socket(AF_PACKET, SOCK_RAW, htons(kEthTypeArp));
    if (sk < 0) return false;

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface_.c_str(), IFNAMSIZ - 1);
    if (::ioctl(sk, SIOCGIFINDEX, &ifr) < 0) { ::close(sk); return false; }

    sockaddr_ll bind_addr{};
    bind_addr.sll_family   = AF_PACKET;
    bind_addr.sll_protocol = htons(kEthTypeArp);
    bind_addr.sll_ifindex  = ifr.ifr_ifindex;
    if (::bind(sk, reinterpret_cast<sockaddr*>(&bind_addr),
               sizeof(bind_addr)) < 0) { ::close(sk); return false; }

    using clock = std::chrono::steady_clock;
    const auto deadline = clock::now() + listen;

    bool conflict_seen = false;
    while (!stop_requested_.load() && clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<
            std::chrono::milliseconds>(deadline - clock::now()).count();
        // 50 ms tick floor matches the BOUND-phase machine — bounds
        // abort latency at 50 ms during long Probe windows.
        const int poll_ms = static_cast<int>(remaining > 50 ? 50 : remaining);

        pollfd pfd{sk, POLLIN, 0};
        const int prc = ::poll(&pfd, 1, poll_ms);
        if (prc <= 0) continue;
        if (!(pfd.revents & POLLIN)) continue;

        std::uint8_t buf[42];
        const ssize_t n = ::recv(sk, buf, sizeof(buf), 0);
        if (n < 28) continue;  // smaller than minimum ARP body — drop

        // ARP header offsets after the 14 B Ethernet header (the
        // SOCK_RAW path delivers full Ethernet frames).
        if (n < 42) continue;
        // Verify ARP h/w type = Ethernet, proto = IPv4 — defensive
        // against any future wide-tap ETH_P_ALL fall-through.
        if (!(buf[14] == 0x00 && buf[15] == 0x01 &&
              buf[16] == 0x08 && buf[17] == 0x00)) {
            continue;
        }
        // sender_proto_ip at offset 14 + 14 = 28
        std::uint32_t sender_ip_be = 0;
        std::memcpy(&sender_ip_be, buf + 28, 4);
        if (sender_ip_be != probed_ip_be) continue;

        // Sender HW at offset 14 + 8 = 22
        bool from_self = true;
        for (std::size_t i = 0; i < 6; ++i) {
            if (buf[22 + i] != dut_mac_[i]) { from_self = false; break; }
        }
        if (from_self) continue;  // our own probe reflected — ignore

        conflict_seen = true;
        break;
    }

    ::close(sk);
    return conflict_seen;
}

int Dhcpv4Client::openClientUdpSocket() {
    // RFC 2131 §4.1: "DHCP messages from a client to a server are sent
    // to the 'DHCP server' port (67), and DHCP messages from a server
    // to a client are sent to the 'DHCP client' port (68)." The DHCP
    // client listens on UDP port 68 — the standard DGRAM socket the
    // kernel routes inbound BOOTP datagrams to.
    //
    // INADDR_ANY:68 receives both unicast (to the iface IP) and
    // broadcast (255.255.255.255) datagrams without further options
    // beyond SO_BROADCAST — the kernel's UDP layer fans broadcast
    // datagrams to every socket bound to the destination port.
    //
    // Bind happens BEFORE the first emitDhcpDiscover so a tester reply
    // arriving inside the harness's tight observer-fire latency (~30 ms
    // at workers=4) cannot race the bind and be silently dropped by
    // the kernel as "no UDP socket bound to port 68".
    int sk = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sk < 0) return -1;

    int one = 1;
    ::setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    ::setsockopt(sk, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    if (!iface_.empty()) {
        // SO_BINDTODEVICE filters reception to packets arriving on the
        // bound iface — keeps the recv stream clean of any host-side
        // DHCP traffic that might leak across netns boundaries on
        // exotic topologies. cap_net_raw covers SO_BINDTODEVICE.
        ::setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE,
                     iface_.c_str(),
                     static_cast<socklen_t>(iface_.size()));
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(kUdpClientPort);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (::bind(sk, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(sk);
        return -1;
    }
    return sk;
}

bool Dhcpv4Client::pollForReply(int                        sk,
                                 std::chrono::milliseconds  timeout,
                                 std::uint32_t              expected_xid_be,
                                 std::uint8_t               expected_msg_type,
                                 std::uint32_t*             out_yiaddr_be,
                                 std::uint32_t*             out_server_id_be,
                                 std::uint32_t*             out_lease_seconds,
                                 std::uint8_t*              out_msg_type,
                                 std::uint32_t*             out_router_be) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    while (!stop_requested_.load()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) break;
        const auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now);
        const int  poll_ms = static_cast<int>(
            std::min<std::chrono::milliseconds::rep>(remain.count(), 100));

        pollfd pfd{};
        pfd.fd     = sk;
        pfd.events = POLLIN;
        const int rc = ::poll(&pfd, 1, poll_ms);
        if (rc <= 0) continue;
        if ((pfd.revents & POLLIN) == 0) continue;

        // recv returns the BOOTP body alone — kernel has stripped
        // Ethernet, IPv4, and UDP headers. RFC 2131 §2 fixes the BOOTP
        // body at 240 B fixed + options trailer; the smallest valid
        // DHCP body is 240 + 4 (magic cookie) + END = 244 B, but most
        // servers emit at minimum 240 + Option 53 (3 B) + END = 244.
        std::uint8_t buf[2048];
        const ssize_t n = ::recv(sk, buf, sizeof(buf), 0);
        if (n < static_cast<ssize_t>(kBootpFixedLen + 4)) continue;

        const std::uint8_t* bp = buf;
        if (bp[0] != kBootReply) continue;

        std::uint32_t xid_be = 0;
        std::memcpy(&xid_be, bp + 4, 4);
        if (xid_be != expected_xid_be) continue;

        if (std::memcmp(bp + 28, dut_mac_.data(), 6) != 0) continue;

        if (bp[236] != 0x63 || bp[237] != 0x82 ||
            bp[238] != 0x53 || bp[239] != 0x63) continue;

        const std::size_t opts_len = static_cast<std::size_t>(n) - kBootpFixedLen;
        const std::uint8_t* opts = bp + kBootpFixedLen;

        // Option 53 (Message Type) gate — `expected_msg_type == 0`
        // means accept any BOOTREPLY (BOUND phase callers want to
        // distinguish ACK vs NAK). Length-1 invariant comes from RFC
        // 2132 RFC 2131 §9.6.
        std::uint8_t  msg_type = 0;
        std::size_t   mt_len   = sizeof(msg_type);
        if (!findDhcpOption(opts, opts_len, 53, &msg_type, &mt_len) ||
            mt_len != 1) continue;
        if (expected_msg_type != 0U && msg_type != expected_msg_type) continue;

        // yiaddr from BOOTP body (offsets 16..19).
        std::uint32_t yiaddr_be = 0;
        std::memcpy(&yiaddr_be, bp + 16, 4);

        // Option 54 (Server Identifier) — required for OFFER, optional
        // on ACK for the SELECTING flow but typically present.
        std::uint32_t server_id_be = 0;
        std::size_t   sid_len      = 4;
        std::uint8_t  sid_bytes[4] = {};
        if (findDhcpOption(opts, opts_len, 54, sid_bytes, &sid_len) && sid_len == 4) {
            std::memcpy(&server_id_be, sid_bytes, 4);
        }

        // Option 51 (IP Address Lease Time, RFC 2132 §9.2) — 4-byte u32
        // in network byte order. Drives the BOUND→RENEWING→REBINDING
        // phase transitions per RFC 2131 §4.4.5. Absent / wrong-length
        // → 0 (phase machine inactive).
        std::uint32_t lease_seconds = 0;
        std::size_t   lt_len        = 4;
        std::uint8_t  lt_bytes[4]   = {};
        if (findDhcpOption(opts, opts_len, 51, lt_bytes, &lt_len) && lt_len == 4) {
            lease_seconds = (static_cast<std::uint32_t>(lt_bytes[0]) << 24) |
                            (static_cast<std::uint32_t>(lt_bytes[1]) << 16) |
                            (static_cast<std::uint32_t>(lt_bytes[2]) <<  8) |
                            (static_cast<std::uint32_t>(lt_bytes[3]) <<  0);
        }

        // §4.7.6.7 CM_05/_06 / RFC 2132 §9.3 Option Overload + RFC 2132 §3.5
        // Option 3 (Router). The router address may live in the main
        // options blob OR (when Option 52 is present) in `sname`
        // (offset 44, 64 B) / `file` (offset 108, 128 B). The walker
        // visits the regions in spec-mandated order — options → file
        // → sname (RFC 2132 §9.3 last sentence) — and writes the LAST
        // 4-byte Option 3 it finds. Absent in every region leaves the
        // slot 0 so the BOUND-time route install is a no-op.
        std::uint32_t router_be = 0;
        auto extract_router_from = [&router_be](const std::uint8_t* base,
                                                 std::size_t         len) {
            std::uint8_t  rb[4]  = {};
            std::size_t   rb_len = 4;
            if (findDhcpOption(base, len, 3, rb, &rb_len) && rb_len == 4) {
                std::memcpy(&router_be, rb, 4);
            }
        };
        extract_router_from(opts, opts_len);
        std::uint8_t  overload     = 0;
        std::size_t   overload_len = 1;
        if (findDhcpOption(opts, opts_len, 52, &overload, &overload_len) &&
            overload_len == 1) {
            // Bit-flag values per RFC 2132 §9.3:
            //   1 = file holds options
            //   2 = sname holds options
            //   3 = both
            if ((overload & 0x01U) != 0U) {
                extract_router_from(bp + 108, 128);
            }
            if ((overload & 0x02U) != 0U) {
                extract_router_from(bp + 44, 64);
            }
        }

        if (out_yiaddr_be     != nullptr) *out_yiaddr_be     = yiaddr_be;
        if (out_server_id_be  != nullptr) *out_server_id_be  = server_id_be;
        if (out_lease_seconds != nullptr) *out_lease_seconds = lease_seconds;
        if (out_msg_type      != nullptr) *out_msg_type      = msg_type;
        if (out_router_be     != nullptr) *out_router_be     = router_be;
        return true;
    }

    return false;
}

void Dhcpv4Client::runLoop(Params params) {
    // §4.7 Phase F: latch the emit-side fault selector before any emit so
    // emitDhcpMessage applies the DISCOVER field mutation. None (every
    // positive case) leaves the wire shape conformant.
    flavor_ = params.flavor;

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<std::uint32_t> xid_dist(1, 0xFFFFFFFFU);

    // Outer lifecycle loop. Each iteration is a fresh INIT → DISCOVER
    // cycle: NAK or lease expiry per RFC 2131 §3.1 / §4.4.5 returns
    // here with `committed_lease_be_` cleared and a freshly-generated
    // xid (the prior cycle's xid is invalidated by the lease release).
    while (!stop_requested_.load()) {
        // Generate a fresh transaction id per RFC 2131 §4.3.2 — the
        // xid scopes the entire DISCOVER → REQUEST → ACK conversation
        // and a NAK invalidates the prior xid.
        const std::uint32_t xid_be = htonl(xid_dist(rng));

        // Bind the recv socket BEFORE any emit so a tester reply
        // landing inside the harness's tight observer-fire latency
        // cannot race the bind. Single socket is reused across
        // DISCOVER→OFFER, REQUEST→ACK, and BOUND-phase NAK polls —
        // port 68 is the same listener throughout per RFC 2131 §4.1.
        int sk = openClientUdpSocket();
        if (sk < 0) return;

        std::uint8_t  attempt           = 0;
        bool          bound             = false;
        std::uint32_t ack_yiaddr_be     = 0;
        std::uint32_t ack_server_be     = 0;
        std::uint32_t ack_lease_seconds = 0;
        std::uint32_t ack_router_be     = 0;
        // §4.7.6.7 CM_12/_13: when retx_first_ms > 0 the inter-DISCOVER
        // wait is computed per attempt as `min(cap, first << N) ±
        // jitter` and supersedes the legacy flat retry_interval_ms.
        const bool exp_backoff_mode =
            (params.retx_first_ms.count() > 0);
        while (!stop_requested_.load() && attempt < params.retry_count) {
            // Phase 0: emit DHCPDISCOVER.
            emitDhcpDiscover(xid_be);

            // Phase 1: wait for DHCPOFFER. In exponential-backoff mode
            // the pollForReply timeout doubles as the inter-DISCOVER
            // gap (no separate retry sleep is needed); the legacy mode
            // still uses `params.offer_wait_ms` + `retry_interval_ms`.
            std::chrono::milliseconds wait_for_offer = params.offer_wait_ms;
            if (exp_backoff_mode) {
                const std::int64_t base_ms = std::min<std::int64_t>(
                    params.retx_cap_ms.count(),
                    params.retx_first_ms.count() *
                        (1LL << static_cast<std::int64_t>(attempt)));
                std::int64_t jitter_ms = 0;
                if (params.retx_jitter_ms.count() > 0) {
                    std::uniform_int_distribution<std::int64_t> jdist(
                        -params.retx_jitter_ms.count(),
                        +params.retx_jitter_ms.count());
                    jitter_ms = jdist(rng);
                }
                const std::int64_t total_ms =
                    std::max<std::int64_t>(0, base_ms + jitter_ms);
                wait_for_offer = std::chrono::milliseconds(total_ms);
            }

            std::uint32_t offered_addr_be = 0;
            std::uint32_t server_id_be    = 0;
            if (!pollForReply(sk, wait_for_offer, xid_be,
                              /*expected_msg_type=*/2,
                              &offered_addr_be, &server_id_be)) {
                ++attempt;
                if (!exp_backoff_mode && attempt < params.retry_count &&
                    !stop_requested_.load()) {
                    std::this_thread::sleep_for(params.retry_interval_ms);
                }
                continue;
            }
            if (stop_requested_.load()) break;

            // Phase 2: emit DHCPREQUEST.
            emitDhcpRequest(xid_be, offered_addr_be, server_id_be);

            // Phase 3: wait for DHCPACK. Capture Option 51 (Lease Time)
            // from the ACK so the BOUND phase machine can schedule
            // T1=lease/2 / T2=lease*7/8 transitions per RFC 2131 §4.4.5.
            // §4.7.6.7 CM_05/_06: also capture Option 3 (Router) — may
            // live in the ACK's main options or, when Option 52 is
            // present, in the BOOTP `sname` / `file` regions.
            std::uint8_t ack_msg_type = 0;
            if (!pollForReply(sk, params.ack_wait_ms, xid_be,
                              /*expected_msg_type=*/5,
                              &ack_yiaddr_be, &ack_server_be,
                              &ack_lease_seconds, &ack_msg_type,
                              &ack_router_be)) {
                ++attempt;
                if (attempt < params.retry_count && !stop_requested_.load()) {
                    std::this_thread::sleep_for(params.retry_interval_ms);
                }
                continue;
            }
            if (stop_requested_.load()) break;

            // BOUND.
            {
                std::lock_guard<std::mutex> lk(lease_mu_);
                committed_lease_be_ = ack_yiaddr_be;
            }
            // §4.7.6.7 CM_05/_06 / RFC 2131 §3.5: apply Option 3
            // (Router) to the host routing table so post-BOUND egress
            // to a different subnet (the spec's IP-UNUSED-ADDRESS step)
            // forwards via the configured gateway. ACKs without
            // Option 3 leave the table untouched (preserves pre-S11
            // behaviour for every other lifecycle case).
            if (ack_router_be != 0U) {
                if (installDefaultRoute(ack_router_be) == 0) {
                    std::lock_guard<std::mutex> lk(lease_mu_);
                    installed_router_be_ = ack_router_be;
                }
            }
            bound = true;
            break;
        }

        // §4.5.6.1 IPv4_AUTOCONF_INTRO_01 fault-injection (Phase F): a
        // host with an operable routable lease MUST NOT also assign an
        // IPv4 Link-Local address (RFC 3927 §1.9 SHOULD NOT). The
        // LeakLinkLocalAfterBind flavor makes this otherwise-compliant
        // DHCP client emit one prohibited 169.254/16 ARP Probe right
        // after BOUND so INTRO_01_NEG can witness the leak. None (every
        // positive case) stays silent — the leak is a real firmware
        // code path, not a harness-injected frame.
        if (bound &&
            params.flavor == Dhcpv4ClientFlavor::LeakLinkLocalAfterBind &&
            !stop_requested_.load()) {
            // 169.254.13.37 — a valid RFC 3927 link-local address (third
            // octet in [1,254]); wire bytes A9 FE 0D 25. is_arp_probe()
            // gates target_proto_ip on the 169.254/16 prefix, so only a
            // link-local-targeted probe trips the INTRO_01 guard.
            constexpr std::uint32_t kLeakLinkLocalProbeTargetBe =
                static_cast<std::uint32_t>(169U)         |
                (static_cast<std::uint32_t>(254U) << 8)  |
                (static_cast<std::uint32_t>(13U)  << 16) |
                (static_cast<std::uint32_t>(37U)  << 24);
            emitArpProbe(kLeakLinkLocalProbeTargetBe);
        }

        // §4.7.6.9 INIT_ALLOC_08/_09/_10 / RFC 2131 §4.4.1: post-BOUND
        // ARP Probe sequence — emit Probe, listen for conflict, then
        // either DECLINE (return to INIT) or Announce (BOUND maintained
        // → fall through to the phase machine). Opt-in via
        // Params::arp_probe_listen_ms; every existing case keeps the
        // default 0 so SELECTING-only / RENEWING / REBINDING tests see
        // the same post-ACK behaviour they did pre-S9.
        if (bound && params.arp_probe_listen_ms.count() > 0 &&
            !stop_requested_.load()) {
            emitArpProbe(ack_yiaddr_be);
            const bool conflict = runArpProbeListener(
                ack_yiaddr_be, params.arp_probe_listen_ms);
            if (conflict) {
                // RFC 2131 §4.4.4: DECLINE the offered address and
                // restart from INIT — skip the phase machine.
                emitDhcpDecline(xid_be, ack_yiaddr_be, ack_server_be);
                ::close(sk);
                std::uint32_t to_remove_decline = 0;
                {
                    std::lock_guard<std::mutex> lk(lease_mu_);
                    committed_lease_be_  = 0;
                    to_remove_decline    = installed_router_be_;
                    installed_router_be_ = 0;
                }
                if (to_remove_decline != 0U) {
                    removeDefaultRoute(to_remove_decline);
                }
                // §4.7.6.3 ALLOCATING_08 / RFC 2131 §3.1 SHOULD: wait a
                // minimum of ten seconds before restarting the
                // configuration process. ALLOCATING_08 trait opts in via
                // [10000, 11000] ms; ALLOCATING_07 / INIT_ALLOC_09 keep
                // the default [0, 0] (instant restart, MUST-only).
                if (params.decline_to_discover_max_ms.count() > 0 &&
                    !stop_requested_.load()) {
                    drawAndSleepRandomMs(
                        rng, stop_requested_,
                        params.decline_to_discover_min_ms.count(),
                        params.decline_to_discover_max_ms.count());
                }
                continue;  // outer while → next SELECTING cycle
            }
            // No conflict: announce ownership per RFC 2131 §4.4.1
            // SHOULD before falling through to the phase machine.
            emitArpAnnounce(ack_yiaddr_be);
        }

        if (!bound) {
            // All attempts exhausted with no ACK — leave
            // committed_lease_be_ at 0 so OpQueryDhcpLease returns the
            // kernel-conventional "no lease" sentinel. The outer loop
            // exits because attempt-exhaustion is a terminal condition
            // (the worker stays parked until abort()), matching the
            // pre-S6b behaviour for SELECTING-failure scenarios.
            ::close(sk);
            while (!stop_requested_.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            return;
        }

        // BOUND/RENEWING/REBINDING phase machine. When the ACK carries
        // Option 51 the machine schedules T1/T2 transitions and polls
        // `sk` for ACK/NAK responses; otherwise it idles in steady
        // BOUND until abort. Returns true if the lifecycle should
        // restart from DISCOVER (NAK in RENEWING/REBINDING per RFC
        // 2131 RFC 2131 §3.1, or lease expiry per §4.4.5).
        const bool init_restart =
            runBoundPhaseMachine(sk, xid_be, ack_server_be, ack_lease_seconds);
        ::close(sk);

        if (!init_restart) return;

        // Reset bound state before the next DISCOVER cycle so
        // OpQueryDhcpLease doesn't briefly observe the stale lease
        // mid-restart. §4.7.6.7 CM_05/_06: also tear down the prior
        // default route — a NAK invalidates the binding (RFC 2131
        // RFC 2131 §3.1) and therefore the routing parameters that came with
        // it. The next BOUND will re-install fresh on the new ACK.
        std::uint32_t to_remove = 0;
        {
            std::lock_guard<std::mutex> lk(lease_mu_);
            committed_lease_be_  = 0;
            to_remove            = installed_router_be_;
            installed_router_be_ = 0;
        }
        if (to_remove != 0U) {
            removeDefaultRoute(to_remove);
        }

        // §4.7.6.9 INIT_ALLOC_01 / RFC 2131 §4.4.1 SHOULD: random wait
        // before the restart DISCOVER. INIT_ALLOC_01 trait requests
        // [1000, 10000] ms; other lifecycle cases keep the default
        // [0, 0] for instant restart (matches pre-S9 behaviour).
        if (params.nak_to_discover_max_ms.count() > 0 && !stop_requested_.load()) {
            drawAndSleepRandomMs(
                rng, stop_requested_,
                params.nak_to_discover_min_ms.count(),
                params.nak_to_discover_max_ms.count());
        }
    }
}

bool Dhcpv4Client::runBoundPhaseMachine(int           sk,
                                         std::uint32_t xid_be,
                                         std::uint32_t server_id_be,
                                         std::uint32_t lease_seconds) {
    using clock = std::chrono::steady_clock;

    // No phase transitions if the server didn't advertise a finite
    // lease. Idle until abort — preserves pre-S6a behaviour for
    // SELECTING-only test cases (S1..S5) whose ServerEmulParams kept
    // the 300s default and whose SCXML deadline (≤6s) catches the
    // verdict long before T1.
    if (lease_seconds == 0U) {
        while (!stop_requested_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return false;
    }

    // Snapshot the BOOTP ciaddr the renewing/rebinding REQUEST MUST
    // carry. committed_lease_be_ is the yiaddr from the matched ACK,
    // mutex-guarded so OpQueryDhcpLease doesn't race the read.
    std::uint32_t client_addr_be = 0;
    {
        std::lock_guard<std::mutex> lk(lease_mu_);
        client_addr_be = committed_lease_be_;
    }

    enum class Phase : std::uint8_t { Bound, Renewing, Rebinding };

    auto bound_at  = clock::now();
    auto t1        = bound_at + std::chrono::seconds(lease_seconds / 2U);
    auto t2        = bound_at + std::chrono::seconds(lease_seconds * 7U / 8U);
    auto lease_end = bound_at + std::chrono::seconds(lease_seconds);
    Phase phase = Phase::Bound;

    // RFC 2131 §4.4.5 in-state retransmission scheduling:
    //   * RENEWING: if no DHCPACK within half the time remaining until
    //     T2, retransmit. Repeat halving down to a 60s floor (which
    //     the fast-envelope harness elides since spec REACQUISITION_05
    //     / ALLOCATING_10 cases use HIGH-LEASE-TIME to keep half-of-
    //     remaining well above 60s naturally; the harness emulates
    //     that bound under the tight 14s case_timeout by floor-skipping).
    //   * REBINDING: same rule with lease_end as the upper bound.
    // `next_retx` is the absolute clock point at which the current
    // phase should re-emit; updated after each emit (the initial emit
    // at T1/T2 entry counts as the first transmission, then halving
    // schedules the retransmissions).
    auto next_retx = clock::time_point::max();

    while (!stop_requested_.load()) {
        const auto now = clock::now();
        if (phase == Phase::Bound && now >= t1) {
            phase = Phase::Renewing;
            emitDhcpRequestRenewing(xid_be, client_addr_be, server_id_be);
            // Schedule first retransmission at half the time remaining
            // until T2. RFC 2131 §4.4.5 specifies a 60s floor; we omit
            // it on the fast envelope (spec REACQUISITION_05 /
            // ALLOCATING_10 use HIGH-LEASE-TIME to keep half-of-
            // remaining above 60s naturally).
            next_retx = now + (t2 - now) / 2;
        }
        if (phase == Phase::Renewing && now >= t2) {
            phase = Phase::Rebinding;
            emitDhcpRequestRebinding(xid_be, client_addr_be);
            // First REBINDING retransmission scheduled at half the
            // time remaining until lease_end (RFC 2131 §4.4.5 same
            // rule with the lease expiry as the upper bound).
            next_retx = now + (lease_end - now) / 2;
        }
        // In-state retransmission. Once the next_retx point is reached
        // and the corresponding phase is still active (no ACK / NAK
        // arrived), re-emit and schedule the next halving.
        if (phase == Phase::Renewing && now >= next_retx && now < t2) {
            emitDhcpRequestRenewing(xid_be, client_addr_be, server_id_be);
            next_retx = now + (t2 - now) / 2;
        }
        if (phase == Phase::Rebinding && now >= next_retx && now < lease_end) {
            emitDhcpRequestRebinding(xid_be, client_addr_be);
            next_retx = now + (lease_end - now) / 2;
        }
        if (now >= lease_end) {
            // RFC 2131 §4.4.5: "If the lease expires before the client
            // receives a DHCPACK, the client moves to INIT state and
            // requests network initialization parameters as if the
            // client were uninitialized." Caller restarts the cycle.
            return true;
        }

        // Poll the bound socket for any BOOTREPLY (ACK or NAK) arriving
        // in response to the RENEWING / REBINDING REQUEST just emitted.
        // 50 ms per tick keeps abort latency bounded and the t1/t2/
        // lease_end edge checks tight, while still draining tester
        // replies promptly. Pre-BOUND ticks (no REQUEST yet emitted)
        // also poll — harmless because no matching reply will arrive.
        std::uint8_t  msg_type      = 0;
        std::uint32_t reply_yiaddr  = 0;
        std::uint32_t reply_server  = 0;
        std::uint32_t reply_lease   = 0;
        const bool got = pollForReply(sk,
                                       std::chrono::milliseconds(50),
                                       xid_be,
                                       /*expected_msg_type=*/0,
                                       &reply_yiaddr, &reply_server,
                                       &reply_lease, &msg_type);
        if (!got) continue;

        if (msg_type == 6U) {
            // RFC 2131 §3.1 / §4.4.5: NAK in RENEWING / REBINDING →
            // return to INIT immediately (do not wait for lease_end).
            return true;
        }
        if (msg_type == 5U && reply_lease != 0U) {
            // ACK in RENEWING / REBINDING with a fresh Option 51 →
            // re-arm the phase machine with the new lease (RFC 2131
            // §4.4.5: "The client MUST reset its retransmission
            // schedule when it acquires a new IP address lease"). The
            // committed yiaddr stays the same — the server granted an
            // extension on the existing binding.
            lease_seconds = reply_lease;
            if (reply_server != 0U) server_id_be = reply_server;
            bound_at  = clock::now();
            t1        = bound_at + std::chrono::seconds(lease_seconds / 2U);
            t2        = bound_at + std::chrono::seconds(lease_seconds * 7U / 8U);
            lease_end = bound_at + std::chrono::seconds(lease_seconds);
            phase     = Phase::Bound;
            next_retx = clock::time_point::max();
        }
        // Any other msg_type (OFFER stragglers from a prior cycle,
        // unknown types) is ignored — phase machine ticks unaffected.
    }

    return false;
}

}  // namespace tc8::dut
