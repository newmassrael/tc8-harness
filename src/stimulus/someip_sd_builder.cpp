#include "stimulus/someip_sd_builder.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

namespace tc8::stimulus {

namespace {

// Big-endian helpers — SOME/IP wire order is network byte order.
void putBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

void putBe24(std::vector<std::uint8_t> &b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

void putBe32(std::vector<std::uint8_t> &b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

// Looks up the first IPv4 address bound to `iface_name`. Returns 0 if the
// interface is absent or carries no IPv4 address.
std::uint32_t ipv4OfInterface(std::string_view iface_name) {
    ifaddrs *head = nullptr;
    if (getifaddrs(&head) != 0 || head == nullptr) {
        return 0;
    }
    std::uint32_t addr = 0;
    for (ifaddrs *a = head; a != nullptr; a = a->ifa_next) {
        if (a->ifa_addr == nullptr) {
            continue;
        }
        if (a->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if (a->ifa_name == nullptr) {
            continue;
        }
        if (iface_name != a->ifa_name) {
            continue;
        }
        addr = reinterpret_cast<sockaddr_in *>(a->ifa_addr)->sin_addr.s_addr;
        break;
    }
    freeifaddrs(head);
    return addr;
}

}  // namespace

std::vector<std::uint8_t> buildFindService(const FindServiceParams &p) {
    // SOME/IP-SD TR_SOMEIP §7.3 wire layout:
    //   [SOME/IP header 16B] [Flags 1B | Reserved 3B] [EntriesLen 4B]
    //   [Entry 16B] [OptionsLen 4B]
    //
    // Payload = 4 (flags/reserved) + 4 (entries_len) + 16 (one entry) + 4
    //         = 28 bytes.
    // SOME/IP length field counts bytes from Request ID onwards:
    //   8 (request_id + proto/iface/msgtype/retcode) + 28 (payload) = 36.
    constexpr std::uint16_t kServiceIdSd = 0xFFFF;
    constexpr std::uint16_t kMethodIdSd = 0x8100;
    constexpr std::uint16_t kClientId = 0x0000;
    constexpr std::uint8_t kProtoVer = 0x01;
    constexpr std::uint8_t kIfaceVer = 0x01;
    constexpr std::uint8_t kMsgTypeNotif = 0x02;  // NOTIFICATION
    constexpr std::uint8_t kReturnCode = 0x00;
    constexpr std::uint32_t kLengthField = 36;
    constexpr std::uint32_t kEntriesLen = 16;
    constexpr std::uint32_t kOptionsLen = 0;
    constexpr std::uint8_t kEntryTypeFind = 0x00;

    std::vector<std::uint8_t> b;
    b.reserve(44);

    // SOME/IP header.
    putBe16(b, kServiceIdSd);
    putBe16(b, kMethodIdSd);
    putBe32(b, kLengthField);
    putBe16(b, kClientId);
    putBe16(b, p.session_id);
    b.push_back(kProtoVer);
    b.push_back(kIfaceVer);
    b.push_back(kMsgTypeNotif);
    b.push_back(kReturnCode);

    // SD header: flags + 24-bit reserved.
    b.push_back(p.sd_flags);
    putBe24(b, 0);

    // Length of Entries Array.
    putBe32(b, kEntriesLen);

    // FindService entry (16B).
    b.push_back(kEntryTypeFind);
    b.push_back(0);  // IndexFirstOptionRun
    b.push_back(0);  // IndexSecondOptionRun
    b.push_back(0);  // #Opt1 (4b) | #Opt2 (4b)
    putBe16(b, p.target.service_id);
    putBe16(b, p.target.instance_id);
    b.push_back(p.target.major_version);
    putBe24(b, p.target.ttl);
    putBe32(b, p.target.minor_version);

    // Length of Options Array = 0 (no options).
    putBe32(b, kOptionsLen);

    return b;
}

std::vector<std::uint8_t> buildFindServiceWithOption(const FindServiceParams &p,
                                                     const Ipv4Endpoint &endpoint) {
    // 56 B = 16 (SOME/IP header) + 4 (flags+reserved) + 4 (entries_len)
    //      + 16 (entry) + 4 (options_len) + 12 (one IPv4 Endpoint option).
    // Length field = 56 - 8 (header bytes before request_id) = 48.
    constexpr std::uint16_t kServiceIdSd = 0xFFFF;
    constexpr std::uint16_t kMethodIdSd = 0x8100;
    constexpr std::uint16_t kClientId = 0x0000;
    constexpr std::uint8_t kProtoVer = 0x01;
    constexpr std::uint8_t kIfaceVer = 0x01;
    constexpr std::uint8_t kMsgTypeNotif = 0x02;
    constexpr std::uint8_t kReturnCode = 0x00;
    constexpr std::uint32_t kLengthField = 48;
    constexpr std::uint32_t kEntriesLen = 16;
    constexpr std::uint32_t kOptionsLen = 12;
    constexpr std::uint8_t kEntryTypeFind = 0x00;
    constexpr std::uint16_t kOptionBodyLen = 9;
    constexpr std::uint8_t kOptionTypeIpv4 = 0x04;

    std::vector<std::uint8_t> b;
    b.reserve(56);

    putBe16(b, kServiceIdSd);
    putBe16(b, kMethodIdSd);
    putBe32(b, kLengthField);
    putBe16(b, kClientId);
    putBe16(b, p.session_id);
    b.push_back(kProtoVer);
    b.push_back(kIfaceVer);
    b.push_back(kMsgTypeNotif);
    b.push_back(kReturnCode);

    b.push_back(p.sd_flags);
    putBe24(b, 0);
    putBe32(b, kEntriesLen);

    // FindService entry — option present but UNREFERENCED (#Opt1=0).
    b.push_back(kEntryTypeFind);
    b.push_back(0);  // IndexFirstOptionRun
    b.push_back(0);  // IndexSecondOptionRun
    b.push_back(0);  // #Opt1=0 | #Opt2=0 — DUT must ignore the option.
    putBe16(b, p.target.service_id);
    putBe16(b, p.target.instance_id);
    b.push_back(p.target.major_version);
    putBe24(b, p.target.ttl);
    putBe32(b, p.target.minor_version);

    putBe32(b, kOptionsLen);

    // IPv4 Endpoint option (12 B).
    putBe16(b, kOptionBodyLen);
    b.push_back(kOptionTypeIpv4);
    b.push_back(0);  // Reserved
    b.push_back(static_cast<std::uint8_t>((endpoint.ipv4_be >> 0) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((endpoint.ipv4_be >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((endpoint.ipv4_be >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((endpoint.ipv4_be >> 24) & 0xFF));
    b.push_back(0);  // Reserved
    b.push_back(endpoint.l4proto);
    putBe16(b, endpoint.port);

    return b;
}

std::vector<std::uint8_t> buildOfferService(const OfferServiceTarget &t) {
    // Wire layout mirrors buildFindService — 16 B SOME/IP + 4 B SD flags/
    // reserved + 4 B EntriesLen=16 + 16 B Type-0x01 entry + 4 B OptionsLen=0
    // = 44 B. Length field counts from request_id forward = 8 + 28 = 36.
    constexpr std::uint16_t kServiceIdSd  = 0xFFFF;
    constexpr std::uint16_t kMethodIdSd   = 0x8100;
    constexpr std::uint16_t kClientId     = 0x0000;
    constexpr std::uint8_t  kProtoVer     = 0x01;
    constexpr std::uint8_t  kIfaceVer     = 0x01;
    constexpr std::uint8_t  kMsgTypeNotif = 0x02;
    constexpr std::uint8_t  kReturnCode   = 0x00;
    constexpr std::uint32_t kLengthField  = 36;
    constexpr std::uint32_t kEntriesLen   = 16;
    constexpr std::uint32_t kOptionsLen   = 0;
    constexpr std::uint8_t  kEntryTypeOffer = 0x01;
    constexpr std::uint8_t  kSdFlags      = 0xC0;

    std::vector<std::uint8_t> b;
    b.reserve(44);

    putBe16(b, kServiceIdSd);
    putBe16(b, kMethodIdSd);
    putBe32(b, kLengthField);
    putBe16(b, kClientId);
    putBe16(b, t.session_id);
    b.push_back(kProtoVer);
    b.push_back(kIfaceVer);
    b.push_back(kMsgTypeNotif);
    b.push_back(kReturnCode);

    b.push_back(kSdFlags);
    putBe24(b, 0);
    putBe32(b, kEntriesLen);

    b.push_back(kEntryTypeOffer);
    b.push_back(0);                 // IndexFirstOptionRun
    b.push_back(0);                 // IndexSecondOptionRun
    b.push_back(0);                 // #Opt1 (4b) | #Opt2 (4b)
    putBe16(b, t.service_id);
    putBe16(b, t.instance_id);
    b.push_back(t.major_version);
    putBe24(b, t.ttl);              // ttl == 0 -> StopOfferService per SD §4.2
    putBe32(b, t.minor_version);

    putBe32(b, kOptionsLen);

    return b;
}

int emitOfferServiceMulticast(std::string_view iface, const OfferServiceTarget &target,
                              std::chrono::milliseconds pre_emit_wait) {
    if (pre_emit_wait.count() > 0) {
        std::this_thread::sleep_for(pre_emit_wait);
    }
    return sendSdMulticast(buildOfferService(target), iface);
}

std::vector<std::uint8_t>
buildOfferServiceWithEndpoint(const OfferServiceWithEndpointTarget &t) {
    // Wire layout: 16 B SOME/IP + 4 B SD flags + 4 B EntriesLen + 16 B
    // Type 0x01 entry + 4 B OptionsLen + 12 B IPv4 Endpoint option = 56 B.
    // Length field = 8 + 4 + 4 + 16 + 4 + 12 = 48.
    constexpr std::uint16_t kServiceIdSd     = 0xFFFF;
    constexpr std::uint16_t kMethodIdSd      = 0x8100;
    constexpr std::uint16_t kClientId        = 0x0000;
    constexpr std::uint8_t  kProtoVer        = 0x01;
    constexpr std::uint8_t  kIfaceVer        = 0x01;
    constexpr std::uint8_t  kMsgTypeNotif    = 0x02;
    constexpr std::uint8_t  kReturnCode      = 0x00;
    constexpr std::uint32_t kLengthField     = 48;
    constexpr std::uint32_t kEntriesLen      = 16;
    constexpr std::uint32_t kOptionsLen      = 12;
    constexpr std::uint8_t  kEntryTypeOffer  = 0x01;
    constexpr std::uint8_t  kSdFlags         = 0xC0;
    constexpr std::uint16_t kOptionBodyLen   = 9;       // IPv4 Endpoint body size.
    constexpr std::uint8_t  kOptionTypeIpv4  = 0x04;    // IPv4 Endpoint.
    constexpr std::uint8_t  kEntryOptionRef  = 0x10;    // #Opt1=1 | #Opt2=0.

    std::vector<std::uint8_t> b;
    b.reserve(56);

    putBe16(b, kServiceIdSd);
    putBe16(b, kMethodIdSd);
    putBe32(b, kLengthField);
    putBe16(b, kClientId);
    putBe16(b, t.service.session_id);
    b.push_back(kProtoVer);
    b.push_back(kIfaceVer);
    b.push_back(kMsgTypeNotif);
    b.push_back(kReturnCode);

    b.push_back(kSdFlags);
    putBe24(b, 0);
    putBe32(b, kEntriesLen);

    // OfferService entry referencing 1 option in run 1.
    b.push_back(kEntryTypeOffer);
    b.push_back(0);                 // IndexFirstOptionRun
    b.push_back(0);                 // IndexSecondOptionRun
    b.push_back(kEntryOptionRef);
    putBe16(b, t.service.service_id);
    putBe16(b, t.service.instance_id);
    b.push_back(t.service.major_version);
    putBe24(b, t.service.ttl);
    putBe32(b, t.service.minor_version);

    putBe32(b, kOptionsLen);

    // IPv4 Endpoint option (12 B). Address bytes are streamed MSB-first
    // from `ipv4_be` which is already in network byte order.
    putBe16(b, kOptionBodyLen);
    b.push_back(kOptionTypeIpv4);
    b.push_back(0);  // Reserved
    b.push_back(static_cast<std::uint8_t>((t.endpoint.ipv4_be >> 0) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((t.endpoint.ipv4_be >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((t.endpoint.ipv4_be >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((t.endpoint.ipv4_be >> 24) & 0xFF));
    b.push_back(0);  // Reserved
    b.push_back(t.endpoint.l4proto);
    putBe16(b, t.endpoint.port);

    return b;
}

int emitOfferServiceMulticastWithEndpoint(std::string_view iface,
                                          const OfferServiceWithEndpointTarget &t,
                                          std::chrono::milliseconds pre_emit_wait) {
    if (pre_emit_wait.count() > 0) {
        std::this_thread::sleep_for(pre_emit_wait);
    }
    OfferServiceWithEndpointTarget filled = t;
    if (filled.endpoint.ipv4_be == 0) {
        filled.endpoint.ipv4_be = ipv4OfInterface(iface);
        if (filled.endpoint.ipv4_be == 0) {
            std::fprintf(stderr,
                         "stimulus: interface '%.*s' has no IPv4 — cannot fill "
                         "OfferService endpoint option\n",
                         static_cast<int>(iface.size()), iface.data());
            return -2;
        }
    }
    return sendSdMulticast(buildOfferServiceWithEndpoint(filled), iface);
}

int sendSdMulticast(const std::vector<std::uint8_t> &datagram, std::string_view iface_name,
                    std::string_view mcast_group, std::uint16_t mcast_port) {
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: socket() failed: %s\n", std::strerror(errno));
        return -1;
    }

    // Pin multicast egress to the intended interface. On veth setups the
    // default-route choice is fragile, and in test netns we want the
    // FindService to leave via veth-tester deterministically.
    const std::uint32_t if_addr = ipv4OfInterface(iface_name);
    if (if_addr == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — "
                     "cannot pin multicast egress\n",
                     static_cast<int>(iface_name.size()), iface_name.data());
        ::close(sock);
        return -2;
    }

    // Bind the source port to the SD port (= mcast_port). vsomeip enforces
    // "SD source port must equal SD port" and silently drops messages from
    // ephemeral ports with `Ignored SD message from unknown port (NNNNN)`.
    // Without this bind, our FindService would never reach vsomeip's SD
    // dispatcher and the DUT would never schedule a solicited reply.
    // SO_REUSEADDR lets successive boot emits skip TIME_WAIT recycling on
    // the same source port.
    const int reuse = 1;
    if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::fprintf(stderr, "stimulus: setsockopt(SO_REUSEADDR) failed: %s\n", std::strerror(errno));
        ::close(sock);
        return -7;
    }
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(mcast_port);
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: bind(SD port %u) failed: %s\n", mcast_port, std::strerror(errno));
        ::close(sock);
        return -7;
    }

    in_addr mcast_if{};
    mcast_if.s_addr = if_addr;
    if (::setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &mcast_if, sizeof(mcast_if)) < 0) {
        std::fprintf(stderr, "stimulus: setsockopt(IP_MULTICAST_IF) failed: %s\n", std::strerror(errno));
        ::close(sock);
        return -3;
    }

    // TTL=1 is the vsomeip default for SD multicast — don't escape the
    // local link.
    const std::uint8_t ttl = 1;
    if (::setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        std::fprintf(stderr, "stimulus: setsockopt(IP_MULTICAST_TTL) failed: %s\n", std::strerror(errno));
        ::close(sock);
        return -4;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(mcast_port);
    if (::inet_pton(AF_INET, std::string(mcast_group).c_str(), &dst.sin_addr) != 1) {
        std::fprintf(stderr, "stimulus: inet_pton('%.*s') failed\n", static_cast<int>(mcast_group.size()),
                     mcast_group.data());
        ::close(sock);
        return -5;
    }

    const ssize_t n =
        ::sendto(sock, datagram.data(), datagram.size(), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    const int saved_errno = errno;
    ::close(sock);

    if (n < 0 || static_cast<std::size_t>(n) != datagram.size()) {
        std::fprintf(stderr, "stimulus: sendto(%.*s:%u) failed: %s (sent=%zd of %zu)\n",
                     static_cast<int>(mcast_group.size()), mcast_group.data(), mcast_port, std::strerror(saved_errno),
                     n, datagram.size());
        return -6;
    }
    return 0;
}

int sendSdUnicast(const std::vector<std::uint8_t> &datagram, std::string_view iface_name,
                  std::uint32_t dst_ip_be, std::uint16_t dst_port) {
    constexpr std::uint16_t kSdPort = 30490;

    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: socket() failed: %s\n", std::strerror(errno));
        return -1;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface_name);
    if (if_addr == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — "
                     "cannot bind unicast SD source\n",
                     static_cast<int>(iface_name.size()), iface_name.data());
        ::close(sock);
        return -2;
    }

    const int reuse = 1;
    if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::fprintf(stderr, "stimulus: setsockopt(SO_REUSEADDR) failed: %s\n", std::strerror(errno));
        ::close(sock);
        return -7;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(kSdPort);
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: bind(SD port %u) failed: %s\n", kSdPort, std::strerror(errno));
        ::close(sock);
        return -7;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    dst.sin_addr.s_addr = dst_ip_be;

    const ssize_t n =
        ::sendto(sock, datagram.data(), datagram.size(), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    const int saved_errno = errno;
    ::close(sock);

    if (n < 0 || static_cast<std::size_t>(n) != datagram.size()) {
        std::fprintf(stderr, "stimulus: sendto(unicast %u.%u.%u.%u:%u) failed: %s (sent=%zd of %zu)\n",
                     (dst_ip_be >> 0) & 0xFFU, (dst_ip_be >> 8) & 0xFFU,
                     (dst_ip_be >> 16) & 0xFFU, (dst_ip_be >> 24) & 0xFFU, dst_port,
                     std::strerror(saved_errno), n, datagram.size());
        return -6;
    }
    return 0;
}

int emitFindServiceBoot(std::string_view iface, const FindServiceTarget &target, const SdBootTiming &timing) {
    std::this_thread::sleep_for(timing.initial_wait);

    // SD §4.2.1: Reboot=1 stays set until Session ID wraps 0xFFFF -> 0x0000.
    // This helper only runs the pre-wrap boot window (session 0x0001 up to
    // timing.total_emits, always < 0xFFFF in practice), so Reboot stays 1
    // on every emit and the Unicast-only 0x40 flag value is intentionally
    // unused here.
    constexpr std::uint8_t kSdFlagsBoot = 0xC0;

    for (int i = 0; i < timing.total_emits; ++i) {
        if (i > 0) {
            std::this_thread::sleep_for(timing.retry_interval);
        }

        FindServiceParams p{};
        p.target = target;
        p.session_id = static_cast<std::uint16_t>(0x0001 + i);
        p.sd_flags = kSdFlagsBoot;

        const auto bytes = buildFindService(p);
        const int rc = sendSdMulticast(bytes, iface);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

std::vector<std::uint8_t> buildSubscribeEventgroup(const SubscribeEventgroupParams &p) {
    // SOME/IP-SD TR_SOMEIP §7.3 + TR_SOMEIP §7.1.3 wire layout for a SubscribeEventgroup:
    //   [SOME/IP header 16B] [Flags 1B | Reserved 3B] [EntriesLen 4B]
    //   [Type 2 entry 16B]   [OptionsLen 4B] [IPv4 Endpoint option 12B]
    //
    // Type 2 entry (subscribe) byte layout:
    //   0: Type (0x06)
    //   1: Index First Option Run (0)
    //   2: Index Second Option Run (0)
    //   3: #Opt1 (4b) | #Opt2 (4b)   — 0x10 (one option in run 1)
    //   4..5: Service ID
    //   6..7: Instance ID
    //   8:    Major Version
    //   9..11: TTL (24-bit BE)
    //   12..13: Reserved (12b) | Counter (4b)
    //   14..15: Eventgroup ID
    //
    // IPv4 Endpoint option (TR_SOMEIP §7.4.3), 12B total:
    //   0..1: Length = 9 (BE, option body size not counting the length field itself)
    //   2:    Type = 0x04 (IPv4 Endpoint)
    //   3:    Reserved = 0
    //   4..7: IPv4 address (network byte order)
    //   8:    Reserved = 0
    //   9:    L4-Proto (0x11 UDP, 0x06 TCP)
    //   10..11: Port (BE)
    //
    // Payload = 4 + 4 + 16 + 4 + 12 = 40 bytes.
    // SOME/IP length field counts bytes from Request ID onwards:
    //   8 (request_id + proto/iface/msgtype/retcode) + 40 (payload) = 48.
    constexpr std::uint16_t kServiceIdSd = 0xFFFF;
    constexpr std::uint16_t kMethodIdSd = 0x8100;
    constexpr std::uint16_t kClientId = 0x0000;
    constexpr std::uint8_t kProtoVer = 0x01;
    constexpr std::uint8_t kIfaceVer = 0x01;
    constexpr std::uint8_t kMsgTypeNotif = 0x02;  // NOTIFICATION
    constexpr std::uint8_t kReturnCode = 0x00;
    constexpr std::uint32_t kLengthFieldCanonical = 48;
    constexpr std::uint32_t kEntriesLenCanonical = 16;
    constexpr std::uint32_t kOptionsLenCanonical = 12;
    // Each extra option contributes (length 2B + type 1B + reserved 1B + body
    // bytes) to the Options Array. Sum once for downstream length math.
    std::uint32_t extra_options_total_bytes = 0;
    for (const auto& eo : p.extra_options) {
        extra_options_total_bytes += static_cast<std::uint32_t>(4 + eo.body.size());
    }
    const std::uint32_t length_field = p.length_override.value_or(
        kLengthFieldCanonical + extra_options_total_bytes);
    const std::uint32_t entries_len_field =
        p.entries_len_override == 0 ? kEntriesLenCanonical : p.entries_len_override;
    const std::uint32_t options_len_field = p.options_len_override.value_or(
        kOptionsLenCanonical + extra_options_total_bytes);
    constexpr std::uint8_t kEntryTypeSubscribe = 0x06;
    constexpr std::uint16_t kOptionBodyLenCanonical = 9;  // Length field value for IPv4 Endpoint.
    const std::uint16_t option_body_len_field =
        p.option_body_len_override.value_or(kOptionBodyLenCanonical);
    constexpr std::uint8_t kOptionTypeIpv4 = 0x04;
    const std::uint8_t option_reserved0 = p.option_reserved0_override.value_or(0);
    const std::uint8_t option_reserved1 = p.option_reserved1_override.value_or(0);
    const std::uint8_t option_type_field = p.option_type_override.value_or(kOptionTypeIpv4);
    const std::uint16_t method_id_field = p.method_id_override.value_or(kMethodIdSd);
    // Canonical #Opt1 nibble is 1 ("one option in run 1"); ETS_115 overrides
    // to a value >1 to assert "more option references than exist".
    constexpr std::uint8_t kNumOptionsFirstCanonical = 1;
    const std::uint8_t num_options_first =
        p.num_options_first_override.value_or(kNumOptionsFirstCanonical) & 0x0F;
    const std::uint8_t num_options_second =
        p.num_options_second_override.value_or(0) & 0x0F;
    const std::uint8_t entry_byte3 = static_cast<std::uint8_t>(
        (num_options_first << 4) | num_options_second);
    const std::uint8_t index_first  = p.index_first_options_override.value_or(0);
    const std::uint8_t index_second = p.index_second_options_override.value_or(0);
    // §5.1.6 SOMEIP_ETS_176 / _177: trailing payload after the Options
    // Array. When `extra_trailing_in_length` is true the bytes are counted
    // by the SOME/IP Length field (canonical 48 + N). When false the
    // length stays at 48 so the trailing bytes are present on-wire but
    // not counted (DUT must still Ack per PRS_SOMEIPSD_00153).
    const std::uint32_t length_with_trailing =
        p.extra_trailing_in_length
            ? static_cast<std::uint32_t>(length_field +
                                         p.extra_trailing_payload.size())
            : length_field;

    std::vector<std::uint8_t> b;
    b.reserve(56 + p.extra_trailing_payload.size());

    // SOME/IP header.
    putBe16(b, kServiceIdSd);
    putBe16(b, method_id_field);
    putBe32(b, length_with_trailing);
    putBe16(b, kClientId);
    putBe16(b, p.session_id);
    b.push_back(kProtoVer);
    b.push_back(kIfaceVer);
    b.push_back(kMsgTypeNotif);
    b.push_back(kReturnCode);

    // SD header: flags + 24-bit reserved.
    b.push_back(p.sd_flags);
    putBe24(b, 0);

    // Length of Entries Array. ETS_123/_124/_125 inject malformed values
    // via SubscribeEventgroupParams::entries_len_override; canonical is 16
    // (one Type 2 entry).
    putBe32(b, entries_len_field);

    // SubscribeEventgroup entry (16B, Type 2).
    b.push_back(kEntryTypeSubscribe);
    b.push_back(index_first);   // IndexFirstOptionRun (canonical 0)
    b.push_back(index_second);  // IndexSecondOptionRun (canonical 0)
    b.push_back(entry_byte3);   // #Opt1 (canonical 1) | #Opt2 (canonical 0)
    putBe16(b, p.target.service_id);
    putBe16(b, p.target.instance_id);
    b.push_back(p.target.major_version);
    putBe24(b, p.target.ttl);
    // Reserved (12b) | Counter (4b) — counter lives in the low nibble of
    // byte 13; reserved bits stay zero.
    b.push_back(0);
    b.push_back(static_cast<std::uint8_t>(p.target.counter & 0x0F));
    putBe16(b, p.target.eventgroup_id);

    // Length of Options Array. Canonical 12 (one IPv4 Endpoint option);
    // ETS_134/_135/_138/_139 override via options_len_override.
    putBe32(b, options_len_field);

    // IPv4 Endpoint option (12B).
    putBe16(b, option_body_len_field);
    b.push_back(option_type_field);     // canonical 0x04 (IPv4 Endpoint); ETS_116/_174 flip
    b.push_back(option_reserved0);  // Reserved (canonical 0; _144 flips)
    // IPv4 address — `ipv4_be` is already in network byte order, stream
    // it MSB-first without additional host-to-network conversion. The
    // `& 0xFF` masks defeat narrowing warnings under `-Wconversion`.
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 0) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 24) & 0xFF));
    b.push_back(option_reserved1);  // Reserved (canonical 0; _144 flips)
    b.push_back(p.tester_endpoint.l4proto);
    putBe16(b, p.tester_endpoint.port);

    // §5.1.6 SOMEIP_ETS_117 / _175 extra options appended after the
    // canonical IPv4 Endpoint option. Wire layout: Length 2B BE +
    // Type 1B + Reserved 1B + body bytes.
    for (const auto& eo : p.extra_options) {
        putBe16(b, static_cast<std::uint16_t>(eo.body.size()));
        b.push_back(eo.type);
        b.push_back(eo.reserved);
        b.insert(b.end(), eo.body.begin(), eo.body.end());
    }

    // §5.1.6 SOMEIP_ETS_176 / _177 trailing payload (extra bytes after the
    // Options Array). Empty by default; populated only by cases that need
    // unused-data-after-options assertions.
    if (!p.extra_trailing_payload.empty()) {
        b.insert(b.end(), p.extra_trailing_payload.begin(),
                 p.extra_trailing_payload.end());
    }

    return b;
}

namespace {

// One SubscribeEventgroup emit. Subscribe is sent UNICAST to the DUT's
// SD endpoint per SD §4.2 (vsomeip drops multicast-addressed Subscribes
// silently). vsomeip additionally enforces SD source-port = SD port:
// packets arriving from an ephemeral source port are logged as "Ignored
// SD message from unknown port" and dropped, so the sending socket binds
// explicitly to the SD port (30490). The tester endpoint advertised in
// the option is the port the DUT should send its Ack to — kept as the
// SD port as well to mirror real-client behaviour; pcap on the tester
// iface captures the Ack regardless of whether anything is bound there.
int subscribeOnce(const SubscribeEventgroupTarget &target, std::uint8_t sd_flags, std::uint16_t session_id,
                  std::string_view iface, const SubscribeDestination &dest, std::uint8_t l4proto = 0x11) {
    constexpr std::uint16_t kSdPort = 30490;

    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: socket() failed: %s\n", std::strerror(errno));
        return -1;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — "
                     "cannot advertise tester endpoint in subscribe option\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return -2;
    }

    // SO_REUSEADDR so two successive emits on the same SD port don't
    // race each other during TIME_WAIT recycling; vsomeip/DUT also holds
    // 30490 if the tester netns shares port namespace (it doesn't here,
    // but the flag is harmless on an otherwise-idle port).
    const int reuse = 1;
    if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::fprintf(stderr, "stimulus: setsockopt(SO_REUSEADDR) failed: %s\n", std::strerror(errno));
        ::close(sock);
        return -7;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(kSdPort);
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: bind(SD port %u) failed: %s\n", kSdPort, std::strerror(errno));
        ::close(sock);
        return -7;
    }

    SubscribeEventgroupParams p{};
    p.target = target;
    p.tester_endpoint.ipv4_be = if_addr;  // already network byte order from ifaddrs.
    p.tester_endpoint.port = kSdPort;
    p.tester_endpoint.l4proto = l4proto;
    p.session_id = session_id;
    p.sd_flags = sd_flags;
    const auto datagram = buildSubscribeEventgroup(p);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dest.port);
    dst.sin_addr.s_addr = dest.ipv4_be;

    const ssize_t n =
        ::sendto(sock, datagram.data(), datagram.size(), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    const int saved_errno = errno;
    ::close(sock);

    if (n < 0 || static_cast<std::size_t>(n) != datagram.size()) {
        std::fprintf(stderr, "stimulus: sendto(unicast dut:%u) failed: %s (sent=%zd of %zu)\n", dest.port,
                     std::strerror(saved_errno), n, datagram.size());
        return -6;
    }
    return 0;
}

}  // namespace

std::vector<std::uint8_t>
buildMultiSubscribeEventgroup(const MultiSubscribeEventgroupParams &p) {
    // Same wire layout as buildSubscribeEventgroup but the entries
    // array carries N Type 2 entries instead of 1. All entries share
    // one option run (run 0 → single IPv4 Endpoint option in run 1).
    constexpr std::uint16_t kServiceIdSd = 0xFFFF;
    constexpr std::uint16_t kMethodIdSd = 0x8100;
    constexpr std::uint16_t kClientId = 0x0000;
    constexpr std::uint8_t kProtoVer = 0x01;
    constexpr std::uint8_t kIfaceVer = 0x01;
    constexpr std::uint8_t kMsgTypeNotif = 0x02;
    constexpr std::uint8_t kReturnCode = 0x00;
    constexpr std::uint8_t kEntryTypeSubscribe = 0x06;
    constexpr std::uint16_t kOptionBodyLen = 9;
    constexpr std::uint8_t kOptionTypeIpv4 = 0x04;

    const std::uint32_t entries_len_actual =
        static_cast<std::uint32_t>(16 * p.entries.size());
    // §5.1.6 SOMEIP_ETS_114: caller-supplied entries_len_override (non-zero)
    // injects a value diverging from the actual entry-bytes count; default
    // (0) means "use the actual computed value".
    const std::uint32_t entries_len =
        p.entries_len_override == 0 ? entries_len_actual : p.entries_len_override;
    constexpr std::uint32_t kOptionsLen = 12;
    // SOME/IP Length field still counts the ACTUAL entries bytes (so the
    // wire layout is internally consistent: header reads X entries-bytes
    // even when EntriesLen field lies). The mismatch is the spec hook.
    const std::uint32_t length_field =
        8 + 4 + 4 + entries_len_actual + 4 + kOptionsLen;

    std::vector<std::uint8_t> b;
    b.reserve(16 + 4 + 4 + entries_len + 4 + kOptionsLen);

    putBe16(b, kServiceIdSd);
    putBe16(b, kMethodIdSd);
    putBe32(b, length_field);
    putBe16(b, kClientId);
    putBe16(b, p.session_id);
    b.push_back(kProtoVer);
    b.push_back(kIfaceVer);
    b.push_back(kMsgTypeNotif);
    b.push_back(kReturnCode);

    b.push_back(p.sd_flags);
    putBe24(b, 0);

    putBe32(b, entries_len);

    for (const auto &t : p.entries) {
        b.push_back(kEntryTypeSubscribe);
        b.push_back(0);     // IndexFirstOptionRun
        b.push_back(0);     // IndexSecondOptionRun
        b.push_back(0x10);  // #Opt1=1 | #Opt2=0
        putBe16(b, t.service_id);
        putBe16(b, t.instance_id);
        b.push_back(t.major_version);
        putBe24(b, t.ttl);
        b.push_back(0);
        b.push_back(static_cast<std::uint8_t>(t.counter & 0x0F));
        putBe16(b, t.eventgroup_id);
    }

    putBe32(b, kOptionsLen);

    putBe16(b, kOptionBodyLen);
    b.push_back(kOptionTypeIpv4);
    b.push_back(0);
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 0) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((p.tester_endpoint.ipv4_be >> 24) & 0xFF));
    b.push_back(0);
    b.push_back(p.tester_endpoint.l4proto);
    putBe16(b, p.tester_endpoint.port);

    return b;
}

int emitMultiSubscribeEventgroup(std::string_view iface,
                                 const std::vector<SubscribeEventgroupTarget> &entries,
                                 std::chrono::milliseconds pre_emit_wait,
                                 const SubscribeDestination &dest) {
    std::this_thread::sleep_for(pre_emit_wait);

    if (entries.empty()) {
        return 0;
    }

    constexpr std::uint16_t kSdPort = 30490;

    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: multi-subscribe socket() failed: %s\n",
                     std::strerror(errno));
        return -1;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — "
                     "cannot advertise tester endpoint in multi-subscribe option\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return -2;
    }

    const int reuse = 1;
    if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::fprintf(stderr, "stimulus: multi-subscribe SO_REUSEADDR failed: %s\n",
                     std::strerror(errno));
        ::close(sock);
        return -3;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(kSdPort);
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: multi-subscribe bind(SD port %u) failed: %s\n",
                     kSdPort, std::strerror(errno));
        ::close(sock);
        return -4;
    }

    MultiSubscribeEventgroupParams p{};
    p.entries = entries;
    p.tester_endpoint.ipv4_be = if_addr;
    p.tester_endpoint.port = kSdPort;
    p.tester_endpoint.l4proto = 0x11;
    p.session_id = 0x0001;
    p.sd_flags = 0xC0;
    const auto datagram = buildMultiSubscribeEventgroup(p);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dest.port);
    dst.sin_addr.s_addr = dest.ipv4_be;

    const ssize_t n = ::sendto(sock, datagram.data(), datagram.size(), 0,
                               reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    const int saved_errno = errno;
    ::close(sock);

    if (n < 0 || static_cast<std::size_t>(n) != datagram.size()) {
        std::fprintf(stderr, "stimulus: multi-subscribe sendto(dut:%u) failed: %s (sent=%zd of %zu)\n",
                     dest.port, std::strerror(saved_errno), n, datagram.size());
        return -5;
    }
    return 0;
}

int emitMultiSubscribeEventgroupRaw(std::string_view iface,
                                    MultiSubscribeEventgroupParams params,
                                    std::chrono::milliseconds pre_emit_wait,
                                    const SubscribeDestination &dest) {
    std::this_thread::sleep_for(pre_emit_wait);

    if (params.entries.empty()) {
        return 0;
    }

    constexpr std::uint16_t kSdPort = 30490;

    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: multi-subscribe-raw socket() failed: %s\n",
                     std::strerror(errno));
        return -1;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — "
                     "cannot advertise tester endpoint in multi-subscribe-raw option\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return -2;
    }

    const int reuse = 1;
    if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::fprintf(stderr, "stimulus: multi-subscribe-raw SO_REUSEADDR failed: %s\n",
                     std::strerror(errno));
        ::close(sock);
        return -3;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(kSdPort);
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: multi-subscribe-raw bind(SD port %u) failed: %s\n",
                     kSdPort, std::strerror(errno));
        ::close(sock);
        return -4;
    }

    if (params.tester_endpoint.ipv4_be == 0) {
        params.tester_endpoint.ipv4_be = if_addr;
        params.tester_endpoint.port = kSdPort;
        if (params.tester_endpoint.l4proto == 0) {
            params.tester_endpoint.l4proto = 0x11;
        }
    }
    const auto datagram = buildMultiSubscribeEventgroup(params);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dest.port);
    dst.sin_addr.s_addr = dest.ipv4_be;

    const ssize_t n = ::sendto(sock, datagram.data(), datagram.size(), 0,
                               reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    const int saved_errno = errno;
    ::close(sock);

    if (n < 0 || static_cast<std::size_t>(n) != datagram.size()) {
        std::fprintf(stderr, "stimulus: multi-subscribe-raw sendto(dut:%u) failed: %s (sent=%zd of %zu)\n",
                     dest.port, std::strerror(saved_errno), n, datagram.size());
        return -5;
    }
    return 0;
}

int emitSubscribeEventgroupBoot(std::string_view iface, const SubscribeEventgroupTarget &target,
                                const SdBootTiming &timing, const SubscribeDestination &dest) {
    std::this_thread::sleep_for(timing.initial_wait);

    constexpr std::uint8_t kSdFlagsBoot = 0xC0;

    for (int i = 0; i < timing.total_emits; ++i) {
        if (i > 0) {
            std::this_thread::sleep_for(timing.retry_interval);
        }
        const std::uint16_t session_id = static_cast<std::uint16_t>(0x0001 + i);
        const int rc = subscribeOnce(target, kSdFlagsBoot, session_id, iface, dest);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

int emitSubscribeEventgroupBootTcpOption(std::string_view iface, const SubscribeEventgroupTarget &target,
                                         const SdBootTiming &timing, const SubscribeDestination &dest) {
    std::this_thread::sleep_for(timing.initial_wait);

    constexpr std::uint8_t kSdFlagsBoot = 0xC0;
    constexpr std::uint8_t kL4ProtoTcp = 0x06;

    for (int i = 0; i < timing.total_emits; ++i) {
        if (i > 0) {
            std::this_thread::sleep_for(timing.retry_interval);
        }
        const std::uint16_t session_id = static_cast<std::uint16_t>(0x0001 + i);
        const int rc = subscribeOnce(target, kSdFlagsBoot, session_id, iface, dest, kL4ProtoTcp);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

int emitSubscribeEventgroupOnce(std::string_view iface,
                                const SubscribeEventgroupTarget &target,
                                std::uint16_t session_id, std::uint8_t sd_flags,
                                std::uint8_t l4proto, const SubscribeDestination &dest) {
    return subscribeOnce(target, sd_flags, session_id, iface, dest, l4proto);
}

int emitSubscribeEventgroupRaw(std::string_view iface,
                               SubscribeEventgroupParams params,
                               const SubscribeDestination &dest) {
    constexpr std::uint16_t kSdPort = 30490;

    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: subscribe-raw socket() failed: %s\n", std::strerror(errno));
        return -1;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — "
                     "cannot advertise tester endpoint in subscribe-raw option\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return -2;
    }

    const int reuse = 1;
    if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::fprintf(stderr, "stimulus: subscribe-raw SO_REUSEADDR failed: %s\n", std::strerror(errno));
        ::close(sock);
        return -3;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(kSdPort);
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: subscribe-raw bind(SD port %u) failed: %s\n", kSdPort,
                     std::strerror(errno));
        ::close(sock);
        return -4;
    }

    if (params.tester_endpoint.ipv4_be == 0) {
        params.tester_endpoint.ipv4_be = if_addr;
        params.tester_endpoint.port = kSdPort;
        if (params.tester_endpoint.l4proto == 0) {
            params.tester_endpoint.l4proto = 0x11;
        }
    }
    const auto datagram = buildSubscribeEventgroup(params);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dest.port);
    dst.sin_addr.s_addr = dest.ipv4_be;

    const ssize_t n = ::sendto(sock, datagram.data(), datagram.size(), 0,
                               reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    const int saved_errno = errno;
    ::close(sock);

    if (n < 0 || static_cast<std::size_t>(n) != datagram.size()) {
        std::fprintf(stderr, "stimulus: subscribe-raw sendto(dut:%u) failed: %s (sent=%zd of %zu)\n",
                     dest.port, std::strerror(saved_errno), n, datagram.size());
        return -5;
    }
    return 0;
}

}  // namespace tc8::stimulus
