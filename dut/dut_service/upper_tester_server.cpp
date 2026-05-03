#include "upper_tester_server.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <vector>

#include "tc8/upper_tester_protocol.h"

namespace tc8::dut {

namespace {

// Data port imported from the shared protocol header so tc8-dut's
// listener bind and the tester's stimulus destination are a single
// source of truth (see `tc8/upper_tester_protocol.h::kDataPort`).
constexpr std::uint16_t kDataPort = ::tc8::ut::kDataPort;

// UT RPC requests are bounded by ut::kMaxPayload=256 + small headers,
// but the data listener must accept §4.6.5.4 UDP_FIELDS_12's
// 65 507 B max-length UDP datagram (RFC 768 IPv4 max payload). 65 536
// covers the largest possible IP datagram (header + UDP + payload)
// without dropping. Stack allocation per recvmsg loop iteration —
// fits comfortably in Linux's default 8 MB thread stack.
constexpr std::size_t kRecvBufferLen = 65536;

// Per-spec directed-broadcast silent discard. For a /24 subnet the
// broadcast is the iface IP with the host octet (last byte of NBO
// uint32) forced to 0xFF. Any netmask would require computing the
// real prefix at runtime; the tc8-dut runs in the smoke-test netns
// with a fixed /24 (172.16.0.0/24, see setup-netns.sh), so this
// `getifaddrs`-derived pair is deterministic per process boot.
void discoverInterface(std::uint32_t &iface_ip_be,
                       std::uint32_t &iface_bcast_be) {
    iface_ip_be    = 0;
    iface_bcast_be = 0;
    ifaddrs *ifa = nullptr;
    if (getifaddrs(&ifa) != 0) {
        return;
    }
    for (ifaddrs *p = ifa; p != nullptr; p = p->ifa_next) {
        if (p->ifa_addr == nullptr) continue;
        if (p->ifa_addr->sa_family != AF_INET) continue;
        if ((p->ifa_flags & IFF_LOOPBACK) != 0) continue;
        if ((p->ifa_flags & IFF_UP) == 0) continue;
        const auto *sa = reinterpret_cast<const sockaddr_in*>(p->ifa_addr);
        iface_ip_be = sa->sin_addr.s_addr;
        // Compute the directed broadcast as (ip | ~netmask). iproute2
        // does not always populate `ifa_broadaddr` (observed empty on
        // the smoke-test veth pair), so prefer an explicit netmask-
        // based derivation over the union field.
        std::uint32_t netmask_be = 0xFFFFFFFFU;
        if (p->ifa_netmask != nullptr) {
            const auto *sm = reinterpret_cast<const sockaddr_in*>(p->ifa_netmask);
            netmask_be = sm->sin_addr.s_addr;
        }
        iface_bcast_be = iface_ip_be | (~netmask_be);
        break;
    }
    freeifaddrs(ifa);
}

// Disable TX checksum offload + TCP/UDP/Generic Segmentation Offload
// on `iface`. veth pairs default to CHECKSUM_PARTIAL on transmit and
// rely on the NIC to finalise the L4 checksum; on a real NIC pcap
// captures the post-finalisation bytes, but on veth the packet stays
// in-kernel and the receive end (and pcap) sees the partial form,
// failing RFC 793 §3.1 / RFC 768 pseudo-header validation. §4.8.6.2
// TCP_CHECKSUM_03 reads `captured.tcp_checksum_valid()` to assert the
// DUT-emitted segment's checksum is correct, so the offloads must be
// off for the harness's pcap-side validator to see what the spec is
// asserting. setup-netns.sh would normally do this with `ethtool -K`,
// but ethtool is not in the smoke-test environment's PATH; the same
// SIOCETHTOOL ioctl works directly here, runs as root inside the DUT
// netns, and applies once per tc8-dut boot.
void disableTxOffload(const char *iface) {
    int sk = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sk < 0) return;

    auto issue = [&](std::uint32_t cmd) {
        ifreq ifr{};
        std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        ethtool_value v{};
        v.cmd  = cmd;
        v.data = 0;  // disable
        ifr.ifr_data = reinterpret_cast<char*>(&v);
        if (::ioctl(sk, SIOCETHTOOL, &ifr) < 0 && errno != EOPNOTSUPP) {
            std::fprintf(stderr,
                         "upper-tester: ethtool cmd 0x%x on %s failed: %s\n",
                         cmd, iface, std::strerror(errno));
        }
    };

    // Order matters: the kernel rejects disabling TX-CSUM if TSO or
    // any feature that depends on TX-CSUM is still on, so disable
    // segmentation-offload features first, then the underlying
    // checksum offload.
    issue(ETHTOOL_STSO);    // TCP Segmentation Offload
    issue(ETHTOOL_SGSO);    // Generic Segmentation Offload
    issue(ETHTOOL_STXCSUM); // TX checksum offload
    ::close(sk);
}

int bindUdp(std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return -1;
    int on = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        ::close(fd);
        return -1;
    }
    // IP_PKTINFO on Linux sets up ancillary data with the wire-level
    // destination address, which is how the data listener tells
    // limited-broadcast (255.255.255.255), directed-broadcast
    // (172.16.0.255), and unicast (172.16.0.2) apart for
    // ADDRESSING_01/02.
    if (::setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
        ::close(fd);
        return -1;
    }
    // 200 ms recv timeout so the loop can wake up and check stop_requested_.
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 200 * 1000;
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        ::close(fd);
        return -1;
    }
    // For ADDRESSING_01's limited broadcast: a socket must have
    // SO_BROADCAST set to receive packets destined to the broadcast
    // address on Linux. Setting it enables both send and receive of
    // broadcasts through this fd.
    if (::setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
        ::close(fd);
        return -1;
    }
    // §4.6.5.4 UDP_FIELDS_12: a single 65 507 B UDP datagram must fit
    // in the kernel's socket receive buffer or recvmsg drops it.
    // Linux's default `net.core.rmem_default` (~200 KB) is usually
    // enough but explicit SO_RCVBUF=131072 makes the headroom
    // deterministic across distros / netns sysctl tuning. Errors are
    // ignored — the bind itself is what we treat as success/failure;
    // the buffer sizing is best-effort.
    int rcvbuf = 131072;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

std::uint32_t readBe32(const std::uint8_t *p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
}

std::uint16_t readBe16(const std::uint8_t *p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

// Convert a wire-BE 32-bit IP (stored MSB-first in the byte stream) to
// the host-side uint32 whose memcmp with sockaddr_in::sin_addr.s_addr
// (already in NBO) matches. On a little-endian host this means reversing
// bytes; on BE it's a no-op. Using htonl via explicit byte assembly so
// the builder logic is endian-independent.
std::uint32_t wireIpToNbo(const std::uint8_t *p) {
    // Wire bytes AC 10 00 FF for 172.16.0.255 should produce the
    // sin_addr.s_addr value 0xFF0010AC on an LE host.
    return (static_cast<std::uint32_t>(p[3]) << 24) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
            static_cast<std::uint32_t>(p[0]);
}

void writeBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

void writeBe32(std::vector<std::uint8_t> &b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

void writeNboIp(std::vector<std::uint8_t> &b, std::uint32_t ip_be) {
    // ip_be is stored in host-native layout where byte 0 (LSB on LE)
    // is the MSB of the on-wire address (e.g. 172 for 172.16.0.1).
    // Emit MSB-first on the wire to match the request encoder's
    // convention (see upper_tester_client.cpp::appendIpv4Be).
    b.push_back(static_cast<std::uint8_t>((ip_be >> 0) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 16) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 24) & 0xFFU));
}

}  // namespace

UpperTesterServer::UpperTesterServer() = default;

UpperTesterServer::~UpperTesterServer() {
    stop();
}

bool UpperTesterServer::start() {
    discoverInterface(iface_ip_be_, iface_bcast_be_);

    // Enumerate every non-loopback up AF_INET interface, sorted by name
    // (lexicographic). The primary iface (index 0) drives the legacy
    // single-iface ADL surface (`iface_name_`, `dut_mac_`,
    // `linklocal_autoconf_`); secondary ifaces feed
    // `dhcpv4_clients_[i]` only — §4.7.6.5 USAGE_01 / RFC 2131 §3.6
    // is the sole consumer today, but the registry shape extends
    // cleanly to any future multi-iface case.
    //
    // Sort-by-name is the deterministic tiebreaker: setup-netns.sh
    // names the second pair `veth-dut2-W` so it sorts after the
    // primary `veth-dut-W` on every supported Linux kernel
    // (getifaddrs returns ifaces in unspecified order; explicit sort
    // removes that ambiguity).
    //
    // Pass-through: also disables TX checksum offload on every iface
    // so CHECKSUM_03's pcap-side validator sees finalised checksums on
    // veth (kernel default leaves CHECKSUM_PARTIAL on transmit).
    struct IfaceInfo {
        std::string                 name;
        std::array<std::uint8_t, 6> mac{};
        std::uint32_t               ip_be    = 0;
        std::uint32_t               bcast_be = 0;
    };
    std::vector<IfaceInfo> ifaces;
    {
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
                const auto *sa =
                    reinterpret_cast<const sockaddr_in*>(p->ifa_addr);
                info.ip_be = sa->sin_addr.s_addr;
                std::uint32_t netmask_be = 0xFFFFFFFFU;
                if (p->ifa_netmask != nullptr) {
                    const auto *sm =
                        reinterpret_cast<const sockaddr_in*>(p->ifa_netmask);
                    netmask_be = sm->sin_addr.s_addr;
                }
                info.bcast_be = info.ip_be | (~netmask_be);
                int sk = ::socket(AF_INET, SOCK_DGRAM, 0);
                if (sk >= 0) {
                    ifreq ifr{};
                    std::strncpy(ifr.ifr_name, p->ifa_name, IFNAMSIZ - 1);
                    if (::ioctl(sk, SIOCGIFHWADDR, &ifr) == 0) {
                        std::memcpy(info.mac.data(),
                                    ifr.ifr_hwaddr.sa_data, 6);
                    }
                    ::close(sk);
                }
                ifaces.push_back(std::move(info));
            }
            freeifaddrs(ifa);
        }
    }
    std::sort(ifaces.begin(), ifaces.end(),
              [](const IfaceInfo &a, const IfaceInfo &b) {
                  return a.name < b.name;
              });

    if (!ifaces.empty()) {
        // Primary iface drives the legacy single-iface surface used by
        // §4.4 / §4.5 / §4.8 cases. Overwrites the values
        // `discoverInterface` populated above (which itself only kept
        // the first hit with no sort tiebreaker) so the SCE tests' ADL
        // expectations and the DHCPv4 client[0] both see the canonical
        // primary iface — no drift between the two paths.
        const auto &primary = ifaces.front();
        iface_name_    = primary.name;
        dut_mac_       = primary.mac;
        iface_ip_be_   = primary.ip_be;
        iface_bcast_be_= primary.bcast_be;
    }
    linklocal_autoconf_.bind(iface_name_, dut_mac_, iface_ip_be_);
    dhcpv4_clients_.clear();
    dhcpv4_clients_.reserve(ifaces.size());
    for (const auto &info : ifaces) {
        auto client = std::make_unique<Dhcpv4Client>();
        client->bind(info.name, info.mac);
        dhcpv4_clients_.push_back(std::move(client));
    }

    data_fd_ = bindUdp(kDataPort);
    if (data_fd_ < 0) {
        std::fprintf(stderr, "upper-tester: bind data port %u failed: %s\n",
                     kDataPort, std::strerror(errno));
        return false;
    }
    ut_fd_ = bindUdp(ut::kPort);
    if (ut_fd_ < 0) {
        std::fprintf(stderr, "upper-tester: bind ut port %u failed: %s\n",
                     ut::kPort, std::strerror(errno));
        ::close(data_fd_);
        data_fd_ = -1;
        return false;
    }

    std::fprintf(stdout,
                 "upper-tester: data_port=%u ut_port=%u iface_ip=0x%08x iface_bcast=0x%08x\n",
                 kDataPort, ut::kPort, iface_ip_be_, iface_bcast_be_);

    stop_requested_.store(false);
    data_thread_ = std::thread([this] { dataListenerLoop(data_fd_); });
    ut_thread_   = std::thread([this] { utServerLoop(ut_fd_); });
    return true;
}

void UpperTesterServer::stop() {
    stop_requested_.store(true);
    if (data_thread_.joinable()) data_thread_.join();
    if (ut_thread_.joinable())   ut_thread_.join();
    if (data_fd_ >= 0) { ::close(data_fd_); data_fd_ = -1; }
    if (ut_fd_   >= 0) { ::close(ut_fd_);   ut_fd_   = -1; }

    // Tear down any TCP listeners still alive. Ordered: signal each
    // worker to stop, join, then close fds. Passive workers exit on
    // the next 200 ms poll tick; active connector workers exit either
    // when connect() returns or when shutdown(accepted_fd, RDWR)
    // unblocks them — the close-shutdown sequence is the one general
    // way to abort a blocking connect() from another thread.
    std::lock_guard<std::mutex> lk(tcp_mu_);
    for (auto &kv : tcp_listeners_) {
        TcpListener *l = kv.second.get();
        l->stop.store(true);
        if (l->kind == TcpListenerKind::Active && l->accepted_fd >= 0) {
            ::shutdown(l->accepted_fd, SHUT_RDWR);
        }
        if (l->worker.joinable()) l->worker.join();
        if (l->accepted_fd >= 0) { ::close(l->accepted_fd); l->accepted_fd = -1; }
        if (l->listen_fd   >= 0) { ::close(l->listen_fd);   l->listen_fd   = -1; }
    }
    tcp_listeners_.clear();

    // §4.6.5.5 UDP_USER_INTERFACE_01: close every dynamic receive port.
    {
        std::lock_guard<std::mutex> lk(udp_receive_ports_mu_);
        for (int fd : udp_receive_ports_) {
            if (fd >= 0) ::close(fd);
        }
        udp_receive_ports_.clear();
    }
}

void UpperTesterServer::dataListenerLoop(int fd) {
    std::uint8_t buf[kRecvBufferLen];
    std::uint8_t cbuf[512];
    while (!stop_requested_.load()) {
        sockaddr_in peer{};
        iovec iov{};
        iov.iov_base = buf;
        iov.iov_len  = sizeof(buf);
        msghdr msg{};
        msg.msg_name       = &peer;
        msg.msg_namelen    = sizeof(peer);
        msg.msg_iov        = &iov;
        msg.msg_iovlen     = 1;
        msg.msg_control    = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        const ssize_t n = ::recvmsg(fd, &msg, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            std::fprintf(stderr, "upper-tester: data recvmsg error: %s\n",
                         std::strerror(errno));
            break;
        }

        // Extract original IP destination via IP_PKTINFO.
        std::uint32_t orig_dst_be = 0;
        for (cmsghdr *c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
                in_pktinfo info{};
                std::memcpy(&info, CMSG_DATA(c), sizeof(info));
                orig_dst_be = info.ipi_addr.s_addr;
                break;
            }
        }

        // §4.4.4.5 IPv4_ADDRESSING_02: silently discard directed-
        // broadcast datagrams at the application layer. iface_bcast_be_
        // is the /24 broadcast computed at start()time. Limited
        // broadcast (255.255.255.255) is kept — ADDRESSING_01 expects
        // "DUT received" for that path. Zero `iface_bcast_be_`
        // (getifaddrs failed) degrades to "accept everything", which
        // surfaces as ADDRESSING_02 failing loudly rather than silently
        // masking a config bug.
        if (iface_bcast_be_ != 0 && orig_dst_be == iface_bcast_be_) {
            continue;
        }

        // §4.6.5.6 UDP_INTRODUCTION_02: silently discard multicast
        // datagrams at the application layer. The spec inverts RFC 1122
        // §4.1.1's allow per the automotive security profile. Linux
        // delivers all-systems-multicast (224.0.0.1) to every INADDR_ANY
        // socket regardless of IP_ADD_MEMBERSHIP, so the kernel won't
        // filter for us. Test class D (224.0.0.0/4) via the canonical
        // host-order check.
        if (IN_MULTICAST(ntohl(orig_dst_be))) {
            continue;
        }

        ReceiveRecord rec{};
        rec.src_ip   = peer.sin_addr.s_addr;
        rec.dst_ip   = orig_dst_be;
        rec.src_port = ntohs(peer.sin_port);
        rec.dst_port = kDataPort;
        rec.payload.assign(buf, buf + n);
        rec.populated = true;

        {
            std::lock_guard<std::mutex> lk(log_mu_);
            last_receipt_ = std::move(rec);
        }
    }
}

void UpperTesterServer::utServerLoop(int fd) {
    std::uint8_t buf[kRecvBufferLen];
    while (!stop_requested_.load()) {
        sockaddr_storage peer{};
        socklen_t peer_len = sizeof(peer);
        const ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0,
                                      reinterpret_cast<sockaddr*>(&peer),
                                      &peer_len);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            std::fprintf(stderr, "upper-tester: ut recvfrom error: %s\n",
                         std::strerror(errno));
            break;
        }
        if (n < 2) {
            // Too short to carry opcode + req_id; silent drop.
            continue;
        }
        const std::uint8_t opcode = buf[0];
        const std::uint8_t req_id = buf[1];
        const std::uint8_t response_opcode =
            static_cast<std::uint8_t>(opcode | ut::kResponseBit);

        // Never respond to our own responses. A misbound socket or a
        // tester loopback quirk could otherwise cause an amplification
        // loop between two UT instances on the same bus.
        if ((opcode & ut::kResponseBit) != 0) {
            continue;
        }

        if (opcode == ut::OpGetReceivedUdp) {
            // Params: <listen_port:u16> <expected_dst_ip:u32>
            if (n < 2 + 2 + 4) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint16_t listen_port = readBe16(buf + 2);
            const std::uint32_t expected_dst_be = wireIpToNbo(buf + 4);
            auto rec = lookupReceipt(listen_port, expected_dst_be);

            std::vector<std::uint8_t> body;
            if (rec.has_value()) {
                body.push_back(0x01);  // received
                writeNboIp(body, rec->src_ip);
                writeBe16(body, rec->src_port);
                // payload_len carries the ORIGINAL receipt length (capped
                // at u16 = 65 535), not the truncated copy length. §4.6.5.4
                // UDP_FIELDS_12 verdicts on `ut_recv_payload_len == 65507`
                // — the wire trailer's payload bytes are still truncated to
                // ut::kMaxPayload so the Confirmation datagram stays under
                // MTU, but the size field itself reports what the DUT's
                // app layer actually saw. Smaller receipts (<= 256 B) are
                // unaffected: original_len == truncated_copy_len.
                const std::uint16_t plen = static_cast<std::uint16_t>(
                    std::min<std::size_t>(rec->payload.size(), 0xFFFFu));
                writeBe16(body, plen);
                const std::size_t copy_len = std::min<std::size_t>(
                    rec->payload.size(), ut::kMaxPayload);
                body.insert(body.end(), rec->payload.begin(),
                            rec->payload.begin() + copy_len);
            } else {
                body.push_back(0x00);  // not received
            }
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ut::kStatusOk, body);
            continue;
        }

        if (opcode == ut::OpTriggerSendUdp) {
            // Params: <src_port:u16> <dst_ip:u32> <dst_port:u16>
            //         <payload_len:u16> <payload[]>
            if (n < 2 + 2 + 4 + 2 + 2) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint16_t src_port    = readBe16(buf + 2);
            const std::uint32_t dst_ip_be   = wireIpToNbo(buf + 4);
            const std::uint16_t dst_port    = readBe16(buf + 8);
            const std::uint16_t payload_len = readBe16(buf + 10);
            if (static_cast<std::size_t>(n) < 12u + payload_len) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const bool ok = triggerSendUdp(src_port, dst_ip_be, dst_port,
                                            buf + 12, payload_len);
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ok ? ut::kStatusOk : ut::kStatusSendFailed, {});
            continue;
        }

        if (opcode == ut::OpOpenTcpSocket) {
            // Params: <type:u8> <local_port:u16>
            //         [<remote_ip:u32 BE> <remote_port:u16>]   // type=Active
            //
            // The leading `type` byte routes between the passive and
            // active openers; the active flavour requires a 6 B remote-
            // endpoint trailer. A short request on the active path is
            // kStatusMalformed, not kStatusConnectFailed — the failure
            // is in the UT frame, not the connect() call.
            if (n < 2 + 1 + 2) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint8_t  socket_type = buf[2];
            const std::uint16_t local_port  = readBe16(buf + 3);

            std::vector<std::uint8_t> body;
            std::uint8_t status = ut::kStatusOk;
            std::optional<std::uint8_t> sid;
            if (socket_type == ut::kSocketTypePassive) {
                sid = openTcpPassive(local_port);
                if (!sid.has_value()) status = ut::kStatusBindFailed;
            } else if (socket_type == ut::kSocketTypeActive) {
                if (static_cast<std::size_t>(n) < 2u + 1u + 2u + 4u + 2u) {
                    sendResponse(fd, peer, peer_len, response_opcode, req_id,
                                 ut::kStatusMalformed, {});
                    continue;
                }
                const std::uint32_t remote_ip_be = wireIpToNbo(buf + 5);
                const std::uint16_t remote_port  = readBe16(buf + 9);
                sid = openTcpActive(local_port, remote_ip_be, remote_port);
                if (!sid.has_value()) status = ut::kStatusConnectFailed;
            } else {
                // Unknown type byte — treat as malformed. The status
                // surface deliberately doesn't carry "unknown type"
                // because every valid client sets it from the same
                // header constants; an unknown byte is a frame bug, not
                // an opcode bug.
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            if (sid.has_value()) {
                body.push_back(*sid);
            }
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         status, body);
            continue;
        }

        if (opcode == ut::OpCloseTcpSocket) {
            // Params: <socket_id:u8>
            if (n < 2 + 1) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint8_t socket_id = buf[2];
            const bool ok = closeTcpSocket(socket_id);
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ok ? ut::kStatusOk : ut::kStatusUnknownSocket, {});
            continue;
        }

        if (opcode == ut::OpSendTcpData) {
            // Params: <socket_id:u8> <payload_len:u16> <payload[]>
            if (n < 2 + 1 + 2) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint8_t  socket_id   = buf[2];
            const std::uint16_t payload_len = readBe16(buf + 3);
            if (static_cast<std::size_t>(n) < 5u + payload_len) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            // sendTcpData distinguishes "unknown socket" from "send
            // failure" via two return paths so smoke-test triage stays
            // diagnostic. UnknownSocket = caller asked for an id we
            // never minted; SendFailed = ::send() refused (ENOTCONN on
            // a socket that never reached ESTABLISHED, EPIPE if the
            // peer RST'd, etc.).
            std::uint8_t status = ut::kStatusOk;
            {
                std::lock_guard<std::mutex> lk(tcp_mu_);
                if (tcp_listeners_.find(socket_id) == tcp_listeners_.end()) {
                    status = ut::kStatusUnknownSocket;
                }
            }
            if (status == ut::kStatusOk) {
                const bool ok = sendTcpData(socket_id, buf + 5, payload_len);
                if (!ok) status = ut::kStatusSendFailed;
            }
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         status, {});
            continue;
        }

        if (opcode == ut::OpShutdownTcpSocketWr) {
            // Params: <socket_id:u8>
            if (n < 2 + 1) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint8_t socket_id = buf[2];
            const bool ok = shutdownTcpSocketWr(socket_id);
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ok ? ut::kStatusOk : ut::kStatusUnknownSocket, {});
            continue;
        }

        if (opcode == ut::OpSendTcpDataPattern) {
            // Params: <socket_id:u8> <pattern:u8> <total_len:u16>
            if (n < 2 + 1 + 1 + 2) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint8_t  socket_id = buf[2];
            const std::uint8_t  pattern   = buf[3];
            const std::uint16_t total_len = readBe16(buf + 4);
            std::uint8_t status = ut::kStatusOk;
            {
                std::lock_guard<std::mutex> lk(tcp_mu_);
                if (tcp_listeners_.find(socket_id) == tcp_listeners_.end()) {
                    status = ut::kStatusUnknownSocket;
                }
            }
            if (status == ut::kStatusOk) {
                const bool ok = sendTcpDataPattern(socket_id, pattern, total_len);
                if (!ok) status = ut::kStatusSendFailed;
            }
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         status, {});
            continue;
        }

        if (opcode == ut::OpAbortTcpSocket) {
            // Params: <socket_id:u8>
            if (n < 2 + 1) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint8_t socket_id = buf[2];
            const bool ok = abortTcpSocket(socket_id);
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ok ? ut::kStatusOk : ut::kStatusUnknownSocket, {});
            continue;
        }

        if (opcode == ut::OpReceiveTcpData) {
            // Params: <socket_id:u8> <expected_len:u16> <timeout_ms:u16>
            if (n < 2 + 1 + 2 + 2) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint8_t  socket_id    = buf[2];
            const std::uint16_t expected_len = readBe16(buf + 3);
            const std::uint16_t timeout_ms   = readBe16(buf + 5);

            std::uint8_t status = ut::kStatusOk;
            {
                std::lock_guard<std::mutex> lk(tcp_mu_);
                if (tcp_listeners_.find(socket_id) == tcp_listeners_.end()) {
                    status = ut::kStatusUnknownSocket;
                }
            }
            std::vector<std::uint8_t> body;
            if (status == ut::kStatusOk) {
                const auto bytes = receiveTcpData(socket_id, expected_len, timeout_ms);
                const std::uint16_t received = static_cast<std::uint16_t>(bytes.size());
                body.reserve(2 + bytes.size());
                body.push_back(static_cast<std::uint8_t>((received >> 8) & 0xFFU));
                body.push_back(static_cast<std::uint8_t>(received & 0xFFU));
                body.insert(body.end(), bytes.begin(), bytes.end());
            }
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         status, body);
            continue;
        }

        if (opcode == ut::OpReceiveTcpDataOob) {
            // Params: <socket_id:u8> <expected_len:u16> <timeout_ms:u16>
            if (n < 2 + 1 + 2 + 2) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint8_t  socket_id    = buf[2];
            const std::uint16_t expected_len = readBe16(buf + 3);
            const std::uint16_t timeout_ms   = readBe16(buf + 5);

            std::uint8_t status = ut::kStatusOk;
            {
                std::lock_guard<std::mutex> lk(tcp_mu_);
                if (tcp_listeners_.find(socket_id) == tcp_listeners_.end()) {
                    status = ut::kStatusUnknownSocket;
                }
            }
            std::vector<std::uint8_t> body;
            if (status == ut::kStatusOk) {
                const auto bytes = receiveTcpDataOob(
                    socket_id, expected_len, timeout_ms);
                const std::uint16_t received = static_cast<std::uint16_t>(bytes.size());
                body.reserve(2 + bytes.size());
                body.push_back(static_cast<std::uint8_t>((received >> 8) & 0xFFU));
                body.push_back(static_cast<std::uint8_t>(received & 0xFFU));
                body.insert(body.end(), bytes.begin(), bytes.end());
            }
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         status, body);
            continue;
        }

        if (opcode == ut::OpQueryTcpEstablished) {
            // Params: <socket_id:u8>
            if (n < 2 + 1) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint8_t socket_id = buf[2];
            const auto est = queryTcpEstablished(socket_id);
            std::vector<std::uint8_t> body;
            std::uint8_t status = ut::kStatusOk;
            if (est.has_value()) {
                body.push_back(*est ? std::uint8_t{1} : std::uint8_t{0});
            } else {
                status = ut::kStatusUnknownSocket;
            }
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         status, body);
            continue;
        }

        if (opcode == ut::OpStartLLAutoconf) {
            // Params: 7 × u16 (dhcp_timeout, probe_wait, probe_min,
            //                   probe_max, announce_wait,
            //                   announce_interval, rate_limit_interval)
            if (n < 2 + 14) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            LinklocalAutoconf::Params params{};
            params.dhcp_timeout_ms        = std::chrono::milliseconds(readBe16(buf + 2));
            params.probe_wait_ms          = std::chrono::milliseconds(readBe16(buf + 4));
            params.probe_min_ms           = std::chrono::milliseconds(readBe16(buf + 6));
            params.probe_max_ms           = std::chrono::milliseconds(readBe16(buf + 8));
            params.announce_wait_ms       = std::chrono::milliseconds(readBe16(buf + 10));
            params.announce_interval_ms   = std::chrono::milliseconds(readBe16(buf + 12));
            params.rate_limit_interval_ms = std::chrono::milliseconds(readBe16(buf + 14));
            linklocal_autoconf_.start(params);
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ut::kStatusOk, {});
            continue;
        }

        if (opcode == ut::OpQueryLLAddress) {
            // No params. Response carries u32 BE LL addr (0 if not yet
            // committed). `addr_be` is already in network byte order
            // (LinklocalAutoconf::pickLLAddress returns htonl-output);
            // emit its memory bytes verbatim so the wire matches the
            // codebase's `*_be == NBO bytes in memory` convention.
            // Shift-extracting from the host uint32 instead would
            // double-encode on little-endian hosts (the byte stream
            // would come out reversed).
            const std::uint32_t addr_be = linklocal_autoconf_.currentAddressBe();
            std::vector<std::uint8_t> body(4);
            std::memcpy(body.data(), &addr_be, 4);
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ut::kStatusOk, body);
            continue;
        }

        if (opcode == ut::OpAbortLLAutoconf) {
            // No params. Idempotent on a stopped machine.
            linklocal_autoconf_.abort();
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ut::kStatusOk, {});
            continue;
        }

        if (opcode == ut::OpStartLLAutoconfBuggy) {
            // Params: 7 × u16 timing knobs + 1 × u8 flavor.
            // Wire size = 2 (opcode/req_id) + 14 (timings) + 1 (flavor)
            //           = 17 bytes minimum.
            if (n < 2 + 14 + 1) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            LinklocalAutoconf::Params params{};
            params.dhcp_timeout_ms        = std::chrono::milliseconds(readBe16(buf + 2));
            params.probe_wait_ms          = std::chrono::milliseconds(readBe16(buf + 4));
            params.probe_min_ms           = std::chrono::milliseconds(readBe16(buf + 6));
            params.probe_max_ms           = std::chrono::milliseconds(readBe16(buf + 8));
            params.announce_wait_ms       = std::chrono::milliseconds(readBe16(buf + 10));
            params.announce_interval_ms   = std::chrono::milliseconds(readBe16(buf + 12));
            params.rate_limit_interval_ms = std::chrono::milliseconds(readBe16(buf + 14));
            // Wire byte → enum cast. Unknown values fall through to
            // None inside the emitArpProbe switch (no default branch
            // = -Wswitch protects against a missing case at compile
            // time; an unknown runtime byte produces compliant emit,
            // surfacing as fail_compliant in the negative case's
            // verdict mapping).
            params.flavor = static_cast<LinklocalAutoconfFlavor>(buf[16]);
            linklocal_autoconf_.start(params);
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ut::kStatusOk, {});
            continue;
        }

        if (opcode == ut::OpStartDhcpClient) {
            // Params: <offer_wait:u16> <ack_wait:u16>
            //         <retry_count:u8> <retry_interval:u16>
            //         <nak_to_discover_min:u16> <nak_to_discover_max:u16>
            //         <arp_probe_listen:u16>
            //         <decline_to_discover_min:u16>
            //         <decline_to_discover_max:u16>
            //         <retx_first:u16> <retx_cap:u16> <retx_jitter:u16>
            //         <iface_index:u8>
            // Wire size grows 9 → 13 → 15 → 19 → 25 → 26 bytes across
            // S6b/S9/S10/S12/S13. Legacy 9-byte payloads (S6b and
            // earlier callers) default every later slot to 0 —
            // preserves instant-restart, skip-probe, instant-restart-
            // after-DECLINE, flat-retry, and primary-iface (index=0)
            // behaviour.
            if (n < 2 + 7) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            Dhcpv4Client::Params params{};
            params.offer_wait_ms     = std::chrono::milliseconds(readBe16(buf + 2));
            params.ack_wait_ms       = std::chrono::milliseconds(readBe16(buf + 4));
            params.retry_count       = buf[6];
            params.retry_interval_ms = std::chrono::milliseconds(readBe16(buf + 7));
            if (n >= 2 + 11) {
                params.nak_to_discover_min_ms =
                    std::chrono::milliseconds(readBe16(buf + 9));
                params.nak_to_discover_max_ms =
                    std::chrono::milliseconds(readBe16(buf + 11));
            }
            if (n >= 2 + 13) {
                params.arp_probe_listen_ms =
                    std::chrono::milliseconds(readBe16(buf + 13));
            }
            if (n >= 2 + 15) {
                params.decline_to_discover_min_ms =
                    std::chrono::milliseconds(readBe16(buf + 15));
                params.decline_to_discover_max_ms =
                    std::chrono::milliseconds(readBe16(buf + 17));
            }
            if (n >= 25) {
                // §4.7.6.7 CM_12/_13 trailing 6-byte exponential-
                // backoff slots (3 × u16 at offsets 19-20 / 21-22 /
                // 23-24). Tight bound: reading buf+23 needs n >= 25.
                // Legacy callers (≤ 19-byte payload) leave these at 0,
                // preserving the flat retry_interval_ms schedule.
                params.retx_first_ms =
                    std::chrono::milliseconds(readBe16(buf + 19));
                params.retx_cap_ms =
                    std::chrono::milliseconds(readBe16(buf + 21));
                params.retx_jitter_ms =
                    std::chrono::milliseconds(readBe16(buf + 23));
            }
            std::uint8_t iface_index = 0;
            if (n >= 26) {
                iface_index = buf[25];
            }
            // Out-of-range iface_index → kStatusMalformed (no silent
            // fallback: a wrong-index call is a tester bug worth
            // surfacing, not a protocol mismatch worth tolerating).
            if (iface_index >= dhcpv4_clients_.size()) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            dhcpv4_clients_[iface_index]->start(params);
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ut::kStatusOk, {});
            continue;
        }

        if (opcode == ut::OpQueryDhcpLease) {
            // No params today; iface_index defaults to 0. Future
            // multi-iface lease queries can extend the request with a
            // trailing iface_index byte (same back-compat shape as
            // OpStartDhcpClient). Response carries u32 BE bound lease
            // (0 if not yet bound). `lease_be` is already in NBO;
            // memcpy its memory bytes verbatim per the codebase
            // *_be == NBO bytes convention.
            std::uint32_t lease_be = 0U;
            if (!dhcpv4_clients_.empty()) {
                lease_be = dhcpv4_clients_[0]->currentLeaseBe();
            }
            std::vector<std::uint8_t> body(4);
            std::memcpy(body.data(), &lease_be, 4);
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ut::kStatusOk, body);
            continue;
        }

        if (opcode == ut::OpAbortDhcpClient) {
            // No params today; aborts every registered iface's
            // instance. Per-iface abort can be added later when a case
            // needs to abort one iface while leaving the other
            // running — USAGE_01 doesn't.
            for (auto &client : dhcpv4_clients_) {
                client->abort();
            }
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ut::kStatusOk, {});
            continue;
        }

        if (opcode == ut::OpQueryTcpInfo) {
            // Params: <socket_id:u8>
            if (n < 2 + 1) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint8_t socket_id = buf[2];
            const auto snap = queryTcpInfo(socket_id);
            std::vector<std::uint8_t> body;
            std::uint8_t status = ut::kStatusOk;
            if (snap.has_value()) {
                body.reserve(1 + 4 + 1 + 4);
                body.push_back(snap->state);
                writeBe32(body, snap->rto_us);
                body.push_back(snap->retransmits);
                writeBe32(body, snap->unacked);
            } else {
                status = ut::kStatusUnknownSocket;
            }
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         status, body);
            continue;
        }

        if (opcode == ut::OpCreateUdpReceivePorts) {
            // Params: <count:u8>
            if (n < 2 + 1) {
                sendResponse(fd, peer, peer_len, response_opcode, req_id,
                             ut::kStatusMalformed, {});
                continue;
            }
            const std::uint8_t requested = buf[2];
            const std::uint8_t actual    = createUdpReceivePorts(requested);
            std::vector<std::uint8_t> body;
            body.push_back(actual);
            sendResponse(fd, peer, peer_len, response_opcode, req_id,
                         ut::kStatusOk, body);
            continue;
        }

        sendResponse(fd, peer, peer_len, response_opcode, req_id,
                     ut::kStatusUnknownOpcode, {});
    }
}

void UpperTesterServer::sendResponse(int fd,
                                     const sockaddr_storage &peer,
                                     socklen_t peer_len,
                                     std::uint8_t opcode,
                                     std::uint8_t req_id,
                                     std::uint8_t status,
                                     const std::vector<std::uint8_t> &body) {
    std::vector<std::uint8_t> frame;
    frame.reserve(3 + body.size());
    frame.push_back(opcode);
    frame.push_back(req_id);
    frame.push_back(status);
    frame.insert(frame.end(), body.begin(), body.end());
    ::sendto(fd, frame.data(), frame.size(), 0,
             reinterpret_cast<const sockaddr*>(&peer), peer_len);
}

std::uint8_t UpperTesterServer::createUdpReceivePorts(std::uint8_t count) {
    // §4.6.5.5 UDP_USER_INTERFACE_01: bind `count` UDP SOCK_DGRAM
    // sockets to (INADDR_ANY, ephemeral port=0). Linux's bind(0)
    // assigns each a distinct ephemeral port from the local-port
    // range. The created fds are kept open for the rest of the
    // process lifetime; `stop()` closes them.
    std::uint8_t actual = 0;
    std::lock_guard<std::mutex> lk(udp_receive_ports_mu_);
    for (std::uint8_t i = 0; i < count; ++i) {
        int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0) break;
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port        = htons(0);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(fd);
            break;
        }
        udp_receive_ports_.push_back(fd);
        ++actual;
    }
    return actual;
}

bool UpperTesterServer::triggerSendUdp(std::uint16_t       src_port,
                                        std::uint32_t       dst_ip_be,
                                        std::uint16_t       dst_port,
                                        const std::uint8_t *payload,
                                        std::uint16_t       payload_len) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return false;
    int on = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    ::setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));

    sockaddr_in local{};
    local.sin_family      = AF_INET;
    local.sin_addr.s_addr = iface_ip_be_;  // 0 falls through to INADDR_ANY
    local.sin_port        = htons(src_port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
        ::close(fd);
        return false;
    }

    sockaddr_in remote{};
    remote.sin_family      = AF_INET;
    remote.sin_addr.s_addr = dst_ip_be;
    remote.sin_port        = htons(dst_port);
    const ssize_t rc = ::sendto(fd, payload, payload_len, 0,
                                 reinterpret_cast<sockaddr*>(&remote),
                                 sizeof(remote));
    ::close(fd);
    return rc == static_cast<ssize_t>(payload_len);
}

std::optional<std::uint8_t>
UpperTesterServer::openTcpPassive(std::uint16_t local_port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return std::nullopt;
    int on = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(local_port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::fprintf(stderr,
                     "upper-tester: tcp bind port %u failed: %s\n",
                     local_port, std::strerror(errno));
        ::close(fd);
        return std::nullopt;
    }
    // backlog=1: §4.8.6.1 BASICS only need a single connection per
    // listener. A higher backlog risks queuing a second tester probe
    // (e.g. a stale handshake from the previous case on the same
    // worker) and confounding the established/non-established flag.
    if (::listen(fd, 1) < 0) {
        std::fprintf(stderr,
                     "upper-tester: tcp listen port %u failed: %s\n",
                     local_port, std::strerror(errno));
        ::close(fd);
        return std::nullopt;
    }

    auto listener = std::make_unique<TcpListener>();
    listener->kind       = TcpListenerKind::Passive;
    listener->listen_fd  = fd;
    listener->local_port = local_port;

    std::lock_guard<std::mutex> lk(tcp_mu_);
    const std::uint8_t sid = next_tcp_socket_id_++;
    if (next_tcp_socket_id_ == 0U) next_tcp_socket_id_ = 1U;  // skip 0
    TcpListener *raw = listener.get();
    tcp_listeners_.emplace(sid, std::move(listener));
    raw->worker = std::thread([this, raw] { tcpAcceptorLoop(raw); });
    return sid;
}

std::optional<std::uint8_t>
UpperTesterServer::openTcpActive(std::uint16_t local_port,
                                  std::uint32_t remote_ip_be,
                                  std::uint16_t remote_port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return std::nullopt;
    int on = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    // Bind to (iface_ip, local_port) so the DUT's outbound SYN carries
    // a deterministic source endpoint the tester can filter on. Without
    // an explicit bind Linux assigns an ephemeral source port at
    // connect() time, which the tester would need to learn from the
    // captured SYN — possible but it pushes timing complexity onto the
    // SCXML side. local_port=0 falls back to ephemeral assignment for
    // callers that genuinely don't care.
    sockaddr_in local{};
    local.sin_family      = AF_INET;
    local.sin_addr.s_addr = iface_ip_be_;
    local.sin_port        = htons(local_port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
        std::fprintf(stderr,
                     "upper-tester: tcp active bind port %u failed: %s\n",
                     local_port, std::strerror(errno));
        ::close(fd);
        return std::nullopt;
    }

    auto listener = std::make_unique<TcpListener>();
    listener->kind        = TcpListenerKind::Active;
    listener->listen_fd   = -1;
    listener->accepted_fd = fd;
    listener->local_port  = local_port;
    listener->remote_ip_be = remote_ip_be;
    listener->remote_port  = remote_port;

    std::lock_guard<std::mutex> lk(tcp_mu_);
    const std::uint8_t sid = next_tcp_socket_id_++;
    if (next_tcp_socket_id_ == 0U) next_tcp_socket_id_ = 1U;  // skip 0
    TcpListener *raw = listener.get();
    tcp_listeners_.emplace(sid, std::move(listener));
    raw->worker = std::thread([this, raw, remote_ip_be, remote_port] {
        tcpConnectorLoop(raw, remote_ip_be, remote_port);
    });
    return sid;
}

bool UpperTesterServer::closeTcpSocket(std::uint8_t socket_id) {
    std::unique_ptr<TcpListener> owned;
    {
        std::lock_guard<std::mutex> lk(tcp_mu_);
        auto it = tcp_listeners_.find(socket_id);
        if (it == tcp_listeners_.end()) {
            return false;
        }
        owned = std::move(it->second);
        tcp_listeners_.erase(it);
    }
    // Outside the mutex: signal stop, join, close. Holding tcp_mu_
    // across the join risks a deadlock if the worker ever calls back
    // into the map (it doesn't today, but the lock-shorter path is
    // unconditionally safer). For active sockets the connector thread
    // may be blocked inside connect(); shutdown(RDWR) on the bound fd
    // unblocks it before we close.
    owned->stop.store(true);
    if (owned->kind == TcpListenerKind::Active && owned->accepted_fd >= 0) {
        ::shutdown(owned->accepted_fd, SHUT_RDWR);
    }
    if (owned->worker.joinable()) owned->worker.join();
    if (owned->accepted_fd >= 0) ::close(owned->accepted_fd);
    if (owned->listen_fd   >= 0) ::close(owned->listen_fd);
    return true;
}

std::optional<bool>
UpperTesterServer::queryTcpEstablished(std::uint8_t socket_id) {
    int fd_to_check = -1;
    {
        std::lock_guard<std::mutex> lk(tcp_mu_);
        auto it = tcp_listeners_.find(socket_id);
        if (it == tcp_listeners_.end()) {
            return std::nullopt;
        }
        fd_to_check = it->second->accepted_fd;
    }
    // No connection accepted yet: the listener is in LISTEN, not
    // ESTABLISHED. Per spec §4.8.6.1 BASICS_02 verifies the [established]
    // state literally — "no accepted_fd" means the DUT has not reached
    // it. Return false rather than a surrogate flag so the kernel's
    // view of the FSM remains the only source of truth.
    if (fd_to_check < 0) {
        return false;
    }
    // §4.8.6.1 BASICS_02 spec literal "Verify that the DUT moves on to
    // ESTABLISHED state". Read `tcp_info.tcpi_state` directly from the
    // accepted socket (Linux exposes the FSM state numerically; 1 ==
    // TCP_ESTABLISHED, see <linux/tcp.h>). A getsockopt failure
    // collapses to "not established" — same outcome as if the kernel
    // never reached the state — so the spec assertion is conservative
    // (false positives never possible; false negatives bounded by the
    // syscall reliability, which is functionally infallible on Linux
    // for a still-open fd).
    struct tcp_info info{};
    socklen_t info_len = sizeof(info);
    if (::getsockopt(fd_to_check, IPPROTO_TCP, TCP_INFO, &info, &info_len) < 0) {
        std::fprintf(stderr,
                     "upper-tester: getsockopt(TCP_INFO) failed: %s\n",
                     std::strerror(errno));
        return false;
    }
    return info.tcpi_state == TCP_ESTABLISHED;
}

std::optional<UpperTesterServer::TcpInfoSnapshot>
UpperTesterServer::queryTcpInfo(std::uint8_t socket_id) {
    int fd_to_check = -1;
    {
        std::lock_guard<std::mutex> lk(tcp_mu_);
        auto it = tcp_listeners_.find(socket_id);
        if (it == tcp_listeners_.end()) {
            return std::nullopt;
        }
        fd_to_check = it->second->accepted_fd;
    }
    // §4.8.6.11 RETRANSMISSION_TO_03 needs a kernel-side answer even
    // before the connection has reached ESTABLISHED — but the case
    // never queries before accept() returns, so a missing accepted_fd
    // here is a wire-protocol bug; surface as kStatusUnknownSocket so
    // the caller observes a deterministic "no kernel state to report"
    // response rather than zeroed garbage.
    if (fd_to_check < 0) {
        return std::nullopt;
    }
    struct tcp_info info{};
    socklen_t info_len = sizeof(info);
    if (::getsockopt(fd_to_check, IPPROTO_TCP, TCP_INFO, &info, &info_len) < 0) {
        std::fprintf(stderr,
                     "upper-tester: getsockopt(TCP_INFO) failed: %s\n",
                     std::strerror(errno));
        return std::nullopt;
    }
    TcpInfoSnapshot snap{};
    snap.state       = info.tcpi_state;
    snap.rto_us      = info.tcpi_rto;
    snap.retransmits = info.tcpi_retransmits;
    snap.unacked     = info.tcpi_unacked;
    return snap;
}

bool UpperTesterServer::sendTcpData(std::uint8_t        socket_id,
                                     const std::uint8_t *payload,
                                     std::uint16_t       payload_len) {
    int fd = -1;
    {
        std::lock_guard<std::mutex> lk(tcp_mu_);
        auto it = tcp_listeners_.find(socket_id);
        if (it == tcp_listeners_.end()) return false;
        fd = it->second->accepted_fd;
    }
    if (fd < 0) return false;
    // Loop on partial writes — Linux's send() can return less than
    // `payload_len` under cwnd backpressure or when the send buffer
    // fills. CHECKSUM_03 caps payload at single-digit kB so the loop
    // converges in 1-2 iterations on a healthy connection; on a
    // broken socket the inner call returns -1 and we surface the
    // failure to the caller.
    std::uint16_t written = 0;
    while (written < payload_len) {
        const ssize_t rc = ::send(fd, payload + written,
                                   payload_len - written, MSG_NOSIGNAL);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (rc == 0) return false;
        written = static_cast<std::uint16_t>(written + rc);
    }
    return written == payload_len;
}

bool UpperTesterServer::sendTcpDataPattern(std::uint8_t  socket_id,
                                            std::uint8_t  pattern,
                                            std::uint16_t total_len) {
    int fd = -1;
    {
        std::lock_guard<std::mutex> lk(tcp_mu_);
        auto it = tcp_listeners_.find(socket_id);
        if (it == tcp_listeners_.end()) return false;
        fd = it->second->accepted_fd;
    }
    if (fd < 0) return false;
    if (total_len == 0U) return true;
    std::vector<std::uint8_t> buf(total_len, pattern);
    std::uint16_t written = 0;
    while (written < total_len) {
        const ssize_t rc = ::send(fd, buf.data() + written,
                                   total_len - written, MSG_NOSIGNAL);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (rc == 0) return false;
        written = static_cast<std::uint16_t>(written + rc);
    }
    return written == total_len;
}

bool UpperTesterServer::shutdownTcpSocketWr(std::uint8_t socket_id) {
    int fd = -1;
    {
        std::lock_guard<std::mutex> lk(tcp_mu_);
        auto it = tcp_listeners_.find(socket_id);
        if (it == tcp_listeners_.end()) return false;
        fd = it->second->accepted_fd;
    }
    if (fd < 0) return false;
    return ::shutdown(fd, SHUT_WR) == 0;
}

bool UpperTesterServer::abortTcpSocket(std::uint8_t socket_id) {
    // §4.8.6.5 ABORT primitive: extract the listener under the mutex
    // (mirrors closeTcpSocket's structure), apply SO_LINGER {1,0} so
    // ::close emits RST instead of FIN (socket(7) LINGER semantics),
    // close the connected fd, then close the listen fd if any. Erasing
    // the listener from the map unbinds the socket_id so a subsequent
    // OpQueryTcpEstablished / OpReceiveTcpData returns
    // kStatusUnknownSocket — same surface as a graceful close.
    //
    // For DUT-in-TIME-WAIT (TC8 §4.8.6.5 ABORT_03 phase 3) the
    // SO_LINGER + close path is NOT sufficient: when a socket
    // transitions to TIME-WAIT, Linux's `tcp_time_wait` allocates a
    // tw_sock wrapper and calls `tcp_done(sk)` which moves the
    // user-fd-attached sk to TCP_CLOSE; the actual TIME-WAIT state
    // lives in the tw_sock and is timer-driven (TCP_TIMEWAIT_LEN =
    // 60 s). close() on a TCP_CLOSE-state sk emits no RST, leaving
    // the tw_sock to time out. To force-terminate the tw_sock the
    // helper invokes `ss -K -t dst <peer> src <local>`, which uses
    // sock_diag's SOCK_DESTROY netlink command to kill the matching
    // entry — works on TIME-WAIT, ESTABLISHED, FIN-WAIT-1, and
    // CLOSING uniformly. Active-flavour listeners carry the 4-tuple
    // since OpenTcpActive; passive flavour omits it (passive ABORT
    // is not exercised by §4.8.6.5 today).
    std::unique_ptr<TcpListener> owned;
    {
        std::lock_guard<std::mutex> lk(tcp_mu_);
        auto it = tcp_listeners_.find(socket_id);
        if (it == tcp_listeners_.end()) return false;
        owned = std::move(it->second);
        tcp_listeners_.erase(it);
    }
    owned->stop.store(true);
    if (owned->accepted_fd >= 0) {
        linger lg{};
        lg.l_onoff  = 1;
        lg.l_linger = 0;
        ::setsockopt(owned->accepted_fd, SOL_SOCKET, SO_LINGER,
                     &lg, sizeof(lg));
    }
    // Active flavour: a connector worker may still be inside
    // ::connect() if abort fires on an unestablished socket. Same
    // shutdown(RDWR) escape as closeTcpSocket so the worker exits
    // cleanly before we close the fd.
    if (owned->kind == TcpListenerKind::Active && owned->accepted_fd >= 0) {
        ::shutdown(owned->accepted_fd, SHUT_RDWR);
    }
    if (owned->worker.joinable()) owned->worker.join();
    if (owned->accepted_fd >= 0) ::close(owned->accepted_fd);
    if (owned->listen_fd   >= 0) ::close(owned->listen_fd);

    // Active 4-tuple known: also issue sock_diag SOCK_DESTROY via
    // `ss -K` to terminate any TIME-WAIT residual the close path
    // left behind. No-op for sockets already gone (EST/FW1/CLOSING/
    // LAST-ACK reach CLOSED via the SO_LINGER path above).
    if (owned->kind == TcpListenerKind::Active &&
        owned->remote_port != 0U) {
        char remote_ip[INET_ADDRSTRLEN] = {};
        char local_ip[INET_ADDRSTRLEN]  = {};
        ::inet_ntop(AF_INET, &owned->remote_ip_be,
                     remote_ip, sizeof(remote_ip));
        ::inet_ntop(AF_INET, &iface_ip_be_,
                     local_ip,  sizeof(local_ip));
        // `state all` is required: `ss -t` defaults to ESTABLISHED-
        // only, which omits TIME-WAIT (the very state the helper
        // exists to terminate). The explicit state-all filter makes
        // the kill cover every transitional state without per-state
        // dispatch.
        char cmd[256];
        const int rc = std::snprintf(cmd, sizeof(cmd),
            "ss -K -t state all dst %s dport = %u "
            "src %s sport = %u 2>/dev/null",
            remote_ip, owned->remote_port,
            local_ip,  owned->local_port);
        if (rc > 0 && rc < static_cast<int>(sizeof(cmd))) {
            std::system(cmd);
        }
    }
    return true;
}

std::vector<std::uint8_t>
UpperTesterServer::receiveTcpData(std::uint8_t  socket_id,
                                   std::uint16_t expected_len,
                                   std::uint16_t timeout_ms) {
    int fd = -1;
    {
        std::lock_guard<std::mutex> lk(tcp_mu_);
        auto it = tcp_listeners_.find(socket_id);
        if (it == tcp_listeners_.end()) return {};
        fd = it->second->accepted_fd;
    }
    if (fd < 0 || expected_len == 0U) return {};

    // Use one SO_RCVTIMEO covering the whole budget. Linux's recv()
    // returns whatever is available (down to 1 byte) without waiting
    // for the full buffer, so a single recv() typically suffices for
    // the §4.8.6.8 16-byte payload arriving as one segment. Loop
    // anyway to coalesce a hypothetical multi-segment delivery; on
    // each iteration we re-set the timeout to the remaining budget so
    // a slow trickle doesn't extend past the caller's bound.
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(timeout_ms);

    std::vector<std::uint8_t> buf(expected_len);
    std::uint16_t total = 0;
    while (total < expected_len) {
        const auto now       = std::chrono::steady_clock::now();
        if (now >= deadline) break;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now);
        timeval tv{};
        tv.tv_sec  = static_cast<time_t>(remaining.count() / 1000);
        tv.tv_usec = static_cast<suseconds_t>((remaining.count() % 1000) * 1000);
        if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            break;
        }
        const ssize_t rc = ::recv(fd, buf.data() + total,
                                   static_cast<std::size_t>(expected_len - total),
                                   0);
        if (rc > 0) {
            total = static_cast<std::uint16_t>(total + rc);
            continue;
        }
        if (rc == 0) break;          // peer half-closed
        if (errno == EINTR) continue;
        break;                        // EAGAIN/timeout / other error
    }
    buf.resize(total);
    return buf;
}

std::vector<std::uint8_t>
UpperTesterServer::receiveTcpDataOob(std::uint8_t  socket_id,
                                      std::uint16_t expected_len,
                                      std::uint16_t timeout_ms) {
    int fd = -1;
    {
        std::lock_guard<std::mutex> lk(tcp_mu_);
        auto it = tcp_listeners_.find(socket_id);
        if (it == tcp_listeners_.end()) return {};
        fd = it->second->accepted_fd;
    }
    if (fd < 0 || expected_len == 0U) return {};

    // Single recv(MSG_OOB) — Linux's OOB queue holds at most one byte
    // per URG segment under default sysctl_tcp_stdurg=0 / SO_OOBINLINE
    // off. recv(MSG_OOB) blocks until that byte is available, then
    // returns 1. A retry loop is unnecessary because subsequent OOB
    // reads on the same urg_seq return EINVAL ("no oob data") rather
    // than another byte. Set SO_RCVTIMEO once so a stuck stimulus
    // path returns within the caller's bound.
    timeval tv{};
    tv.tv_sec  = static_cast<time_t>(timeout_ms / 1000U);
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000U) * 1000U);
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return {};
    }

    std::vector<std::uint8_t> buf(expected_len);
    const ssize_t rc = ::recv(fd, buf.data(),
                              static_cast<std::size_t>(expected_len),
                              MSG_OOB);
    if (rc <= 0) return {};
    buf.resize(static_cast<std::size_t>(rc));
    return buf;
}

void UpperTesterServer::tcpConnectorLoop(TcpListener *listener,
                                          std::uint32_t remote_ip_be,
                                          std::uint16_t remote_port) {
    // §4.8.5 active-open backend. Issued on a worker thread so the UT
    // RPC reply can be sent back the moment the bind succeeds — the
    // tester's smoke wall-time should track the SYN→SYN+ACK→ACK round
    // trip, not the UT response latency.
    //
    // This loop runs once: connect(), then exit. A connect() that
    // succeeds leaves the kernel socket in TCP_ESTABLISHED, which is
    // exactly the state OpQueryTcpEstablished's TCP_INFO reads. A
    // connect() that fails (e.g. tester listener absent → kernel RST)
    // leaves the socket in TCP_CLOSE; the spec assertion paths
    // (BASICS_06's "DUT sends SYN" pass guard) still observe the wire
    // SYN regardless of whether the handshake completes.
    sockaddr_in remote{};
    remote.sin_family      = AF_INET;
    remote.sin_addr.s_addr = remote_ip_be;
    remote.sin_port        = htons(remote_port);
    const int rc = ::connect(listener->accepted_fd,
                              reinterpret_cast<sockaddr*>(&remote),
                              sizeof(remote));
    if (rc < 0 && !listener->stop.load()) {
        std::fprintf(stderr,
                     "upper-tester: tcp active connect to port %u failed: %s\n",
                     remote_port, std::strerror(errno));
    }
}

void UpperTesterServer::tcpAcceptorLoop(TcpListener *listener) {
    // One-shot acceptor: poll the listen fd with 200 ms timeout, take
    // the first connection, set established, exit. BASICS_01..03 each
    // open a fresh listener so per-case state is isolated; rerunning
    // accept() in a loop would only create complexity without spec
    // benefit.
    while (!stop_requested_.load() && !listener->stop.load()) {
        pollfd pfd{};
        pfd.fd     = listener->listen_fd;
        pfd.events = POLLIN;
        const int rc = ::poll(&pfd, 1, 200);
        if (rc < 0) {
            if (errno == EINTR) continue;
            std::fprintf(stderr,
                         "upper-tester: tcp poll error: %s\n",
                         std::strerror(errno));
            return;
        }
        if (rc == 0) continue;  // timeout — re-check stop flags
        if ((pfd.revents & POLLIN) == 0) continue;

        sockaddr_in peer{};
        socklen_t   peer_len = sizeof(peer);
        const int afd = ::accept(listener->listen_fd,
                                  reinterpret_cast<sockaddr*>(&peer),
                                  &peer_len);
        if (afd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            std::fprintf(stderr,
                         "upper-tester: tcp accept failed: %s\n",
                         std::strerror(errno));
            return;
        }
        listener->accepted_fd = afd;
        return;
    }
}

std::optional<UpperTesterServer::ReceiveRecord>
UpperTesterServer::lookupReceipt(std::uint16_t listen_port,
                                  std::uint32_t expected_dst_ip_be) {
    std::lock_guard<std::mutex> lk(log_mu_);
    if (!last_receipt_.populated) {
        return std::nullopt;
    }
    if (last_receipt_.dst_port != listen_port) {
        return std::nullopt;
    }
    // A zero `expected_dst_ip_be` matches any destination — caller
    // explicitly opts into "was anything received on this port"
    // semantics. Used by smoke tooling; the spec cases all pass a
    // concrete address.
    if (expected_dst_ip_be != 0 &&
        last_receipt_.dst_ip != expected_dst_ip_be) {
        return std::nullopt;
    }
    return last_receipt_;
}

}  // namespace tc8::dut
