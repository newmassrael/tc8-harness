#include "posix_ut_extensions.h"

#include <ifaddrs.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>

#include "tc8/iface_enumeration.h"
#include "tc8/upper_tester_protocol.h"

namespace tc8::dut {

namespace {
namespace ut = ::tc8::ut;

// Disable TX checksum + segmentation offload on `iface`. veth defaults to
// CHECKSUM_PARTIAL on transmit; pcap then sees the partial form and §4.8.6.2
// CHECKSUM_03's validator fails RFC 793 / RFC 768 pseudo-header checks. ethtool
// is absent from the smoke env PATH, so issue the SIOCETHTOOL ioctl directly.
void disableTxOffload(const char *iface) {
    int sk = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sk < 0) return;
    auto issue = [&](std::uint32_t cmd) {
        ifreq ifr{};
        std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        ethtool_value v{};
        v.cmd = cmd;
        v.data = 0;  // disable
        ifr.ifr_data = reinterpret_cast<char *>(&v);
        if (::ioctl(sk, SIOCETHTOOL, &ifr) < 0 && errno != EOPNOTSUPP) {
            std::fprintf(stderr, "upper-tester: ethtool cmd 0x%x on %s failed: %s\n", cmd, iface,
                         std::strerror(errno));
        }
    };
    // Order: segmentation-offload first, then the underlying TX checksum (the
    // kernel rejects disabling TX-CSUM while a dependent feature is still on).
    issue(ETHTOOL_STSO);
    issue(ETHTOOL_SGSO);
    issue(ETHTOOL_STXCSUM);
    ::close(sk);
}

}  // namespace

void PosixUtExtensions::discoverInterfaces() {
    using ::tc8::iface_enum::IfaceInfo;
    std::vector<IfaceInfo> ifaces;
    ifaddrs *ifa = nullptr;
    if (::getifaddrs(&ifa) == 0) {
        for (ifaddrs *p = ifa; p != nullptr; p = p->ifa_next) {
            if (p->ifa_addr == nullptr) continue;
            if (p->ifa_addr->sa_family != AF_INET) continue;
            if ((p->ifa_flags & IFF_LOOPBACK) != 0) continue;
            if ((p->ifa_flags & IFF_UP) == 0) continue;
            disableTxOffload(p->ifa_name);
            IfaceInfo info;
            info.name = p->ifa_name;
            const auto *sa = reinterpret_cast<const sockaddr_in *>(p->ifa_addr);
            info.ip_be = sa->sin_addr.s_addr;
            std::uint32_t netmask_be = 0xFFFFFFFFU;
            if (p->ifa_netmask != nullptr) {
                const auto *sm = reinterpret_cast<const sockaddr_in *>(p->ifa_netmask);
                netmask_be = sm->sin_addr.s_addr;
            }
            info.bcast_be = info.ip_be | (~netmask_be);
            int sk = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (sk >= 0) {
                ifreq ifr{};
                std::strncpy(ifr.ifr_name, p->ifa_name, IFNAMSIZ - 1);
                if (::ioctl(sk, SIOCGIFHWADDR, &ifr) == 0) {
                    std::memcpy(info.mac.data(), ifr.ifr_hwaddr.sa_data, 6);
                }
                ::close(sk);
            }
            ifaces.push_back(std::move(info));
        }
        freeifaddrs(ifa);
    }
    // getifaddrs yields one entry per AF_INET address — collapse to one per iface
    // (the UI_07/_08 alias must not double-register), then sort by name so the
    // primary / DHCP-client[0] tiebreak is deterministic.
    ifaces = ::tc8::iface_enum::dedupeByName(std::move(ifaces));
    std::sort(ifaces.begin(), ifaces.end(),
              [](const IfaceInfo &a, const IfaceInfo &b) { return a.name < b.name; });

    if (!ifaces.empty()) {
        const auto &primary = ifaces.front();
        iface_name_ = primary.name;
        dut_mac_ = primary.mac;
        iface_ip_be_ = primary.ip_be;
        iface_bcast_be_ = primary.bcast_be;
    }
    linklocal_autoconf_.bind(iface_name_, dut_mac_, iface_ip_be_);
    dhcpv4_clients_.clear();
    dhcpv4_clients_.reserve(ifaces.size());
    for (const auto &info : ifaces) {
        auto client = std::make_unique<Dhcpv4Client>();
        client->bind(info.name, info.mac);
        dhcpv4_clients_.push_back(std::move(client));
    }
}

void PosixUtExtensions::registerOn(ut::UpperTesterServer &server) {
    using std::chrono::milliseconds;

    // 0x0C OpStartLLAutoconf: 7 x u16 timing knobs.
    server.registerOpcode(ut::OpStartLLAutoconf, [this](const std::uint8_t *p, std::size_t n,
                                                        std::uint8_t &st,
                                                        std::vector<std::uint8_t> &) {
        if (n < 14) {
            st = ut::kStatusMalformed;
            return;
        }
        LinklocalAutoconf::Params params{};
        params.dhcp_timeout_ms = milliseconds(ut::readU16(p + 0));
        params.probe_wait_ms = milliseconds(ut::readU16(p + 2));
        params.probe_min_ms = milliseconds(ut::readU16(p + 4));
        params.probe_max_ms = milliseconds(ut::readU16(p + 6));
        params.announce_wait_ms = milliseconds(ut::readU16(p + 8));
        params.announce_interval_ms = milliseconds(ut::readU16(p + 10));
        params.rate_limit_interval_ms = milliseconds(ut::readU16(p + 12));
        linklocal_autoconf_.start(params);
    });

    // 0x0D OpQueryLLAddress: response carries the committed LL address (NBO,
    // 0 if not yet committed). currentAddressBe() is already NBO — emit verbatim.
    server.registerOpcode(ut::OpQueryLLAddress, [this](const std::uint8_t *, std::size_t,
                                                       std::uint8_t &,
                                                       std::vector<std::uint8_t> &body) {
        const std::uint32_t addr_be = linklocal_autoconf_.currentAddressBe();
        std::uint8_t t[4];
        std::memcpy(t, &addr_be, 4);
        body.insert(body.end(), t, t + 4);
    });

    // 0x0E OpAbortLLAutoconf: idempotent.
    server.registerOpcode(ut::OpAbortLLAutoconf, [this](const std::uint8_t *, std::size_t,
                                                        std::uint8_t &, std::vector<std::uint8_t> &) {
        linklocal_autoconf_.abort();
    });

    // 0x0F OpStartLLAutoconfBuggy: 7 x u16 + flavor byte. Unknown flavor values
    // fall through to compliant emit inside LinklocalAutoconf's switch.
    server.registerOpcode(ut::OpStartLLAutoconfBuggy, [this](const std::uint8_t *p, std::size_t n,
                                                             std::uint8_t &st,
                                                             std::vector<std::uint8_t> &) {
        if (n < 15) {
            st = ut::kStatusMalformed;
            return;
        }
        LinklocalAutoconf::Params params{};
        params.dhcp_timeout_ms = milliseconds(ut::readU16(p + 0));
        params.probe_wait_ms = milliseconds(ut::readU16(p + 2));
        params.probe_min_ms = milliseconds(ut::readU16(p + 4));
        params.probe_max_ms = milliseconds(ut::readU16(p + 6));
        params.announce_wait_ms = milliseconds(ut::readU16(p + 8));
        params.announce_interval_ms = milliseconds(ut::readU16(p + 10));
        params.rate_limit_interval_ms = milliseconds(ut::readU16(p + 12));
        params.flavor = static_cast<LinklocalAutoconfFlavor>(p[14]);
        linklocal_autoconf_.start(params);
    });

    // 0x10 OpStartDhcpClient: append-only param growth 7 -> 11 -> 13 -> 17 ->
    // 23 -> 24 params bytes (S2..S13). Legacy callers default later slots to 0.
    server.registerOpcode(ut::OpStartDhcpClient, [this](const std::uint8_t *p, std::size_t n,
                                                        std::uint8_t &st,
                                                        std::vector<std::uint8_t> &) {
        if (n < 7) {
            st = ut::kStatusMalformed;
            return;
        }
        Dhcpv4Client::Params params{};
        params.offer_wait_ms = milliseconds(ut::readU16(p + 0));
        params.ack_wait_ms = milliseconds(ut::readU16(p + 2));
        params.retry_count = p[4];
        params.retry_interval_ms = milliseconds(ut::readU16(p + 5));
        if (n >= 11) {
            params.nak_to_discover_min_ms = milliseconds(ut::readU16(p + 7));
            params.nak_to_discover_max_ms = milliseconds(ut::readU16(p + 9));
        }
        if (n >= 13) {
            params.arp_probe_listen_ms = milliseconds(ut::readU16(p + 11));
        }
        if (n >= 17) {  // decline pair at p+13 / p+15 needs 17 params bytes
            params.decline_to_discover_min_ms = milliseconds(ut::readU16(p + 13));
            params.decline_to_discover_max_ms = milliseconds(ut::readU16(p + 15));
        }
        if (n >= 23) {  // §4.7.6.7 CM_12/_13 exponential-backoff slots
            params.retx_first_ms = milliseconds(ut::readU16(p + 17));
            params.retx_cap_ms = milliseconds(ut::readU16(p + 19));
            params.retx_jitter_ms = milliseconds(ut::readU16(p + 21));
        }
        std::uint8_t iface_index = 0;
        if (n >= 24) {
            iface_index = p[23];
        }
        // §4.5.6.1 / §4.7.6.9 Phase F DHCP-client fault-injection slot. The
        // single flavor byte selects EXACTLY ONE of: an ARP-frame field mutant
        // (Dhcpv4ArpFlavor), a behavioural mutant (Dhcpv4BehaviorFlavor:
        // post-BOUND leak / reply-acceptance bypass), or a DHCP-message field
        // mutant (Dhcpv4ClientFlavor) — route by value so each firmware
        // dispatch site switches over only its own domain. Unknown bytes leave
        // all three at None (compliant), so a zero-padded legacy request can
        // never inject a fault.
        if (n >= 25) {
            const std::uint8_t fb = p[24];
            if (fb == ut::kDhcpFlavorProbeSenderIpNonzero ||
                fb == ut::kDhcpFlavorAnnounceSenderIpWrong) {
                params.arp_flavor = static_cast<Dhcpv4ArpFlavor>(fb);
            } else if (fb == ut::kDhcpFlavorLeakLinkLocalAfterBind ||
                       fb == ut::kDhcpFlavorAcceptMismatchedXidOffer ||
                       fb == ut::kDhcpFlavorProceedOnLoneAck ||
                       fb == ut::kDhcpFlavorRetxNoBackoff ||
                       fb == ut::kDhcpFlavorRetxExceedCap ||
                       fb == ut::kDhcpFlavorNakRestartNoDelay) {
                params.behavior_flavor = static_cast<Dhcpv4BehaviorFlavor>(fb);
            } else {
                params.flavor = static_cast<Dhcpv4ClientFlavor>(fb);
            }
        }
        // Out-of-range index is a tester bug worth surfacing, not a transport
        // mismatch worth tolerating (no silent fallback to 0).
        if (iface_index >= dhcpv4_clients_.size()) {
            st = ut::kStatusMalformed;
            return;
        }
        dhcpv4_clients_[iface_index]->start(params);
    });

    // 0x11 OpQueryDhcpLease: bound lease of iface 0 (NBO, 0 if not bound).
    server.registerOpcode(ut::OpQueryDhcpLease, [this](const std::uint8_t *, std::size_t,
                                                       std::uint8_t &,
                                                       std::vector<std::uint8_t> &body) {
        std::uint32_t lease_be = 0U;
        if (!dhcpv4_clients_.empty()) {
            lease_be = dhcpv4_clients_[0]->currentLeaseBe();
        }
        std::uint8_t t[4];
        std::memcpy(t, &lease_be, 4);
        body.insert(body.end(), t, t + 4);
    });

    // 0x12 OpAbortDhcpClient: aborts every registered iface's instance.
    server.registerOpcode(ut::OpAbortDhcpClient, [this](const std::uint8_t *, std::size_t,
                                                        std::uint8_t &, std::vector<std::uint8_t> &) {
        for (auto &client : dhcpv4_clients_) {
            client->abort();
        }
    });
}

}  // namespace tc8::dut
