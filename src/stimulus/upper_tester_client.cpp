#include "stimulus/upper_tester_client.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "tc8/unperformed_stimulus.h"

#include "stimulus/arp_builder.h"  // sendRawEthernet
#include "stimulus/ipv4_frame_builder.h"
#include "stimulus/udp_datagram_builder.h"

namespace tc8::stimulus {

namespace {

void appendBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

void appendIpv4Be(std::vector<std::uint8_t> &b, std::uint32_t ip_be) {
    b.push_back(static_cast<std::uint8_t>((ip_be >> 0) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 16) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 24) & 0xFFU));
}

// A receive tap on `iface` for the DUT's UT replies, opened BEFORE the request
// goes out (the DUT answers within ~500 us). AF_PACKET, so it hears a reply
// whatever Ethernet destination the DUT chose — see sendUpperTesterRequestAwaited
// for why that is the whole point — with promiscuous membership so a physical NIC
// does not filter such a frame in hardware (a veth delivers it regardless; the
// membership is refcounted by the kernel and released on close). -1 on failure.
int openUtReplyTap(std::string_view iface) {
    const int fd = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_IP));
    if (fd < 0) {
        return -1;
    }
    const unsigned int ifindex = ::if_nametoindex(std::string(iface).c_str());
    sockaddr_ll ll{};
    ll.sll_family   = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_IP);
    ll.sll_ifindex  = static_cast<int>(ifindex);
    if (ifindex == 0 || ::bind(fd, reinterpret_cast<const sockaddr *>(&ll), sizeof(ll)) < 0) {
        ::close(fd);
        return -1;
    }
    packet_mreq mr{};
    mr.mr_ifindex = static_cast<int>(ifindex);
    mr.mr_type    = PACKET_MR_PROMISC;
    if (::setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// The UT payload of `frame` when it is a UDP datagram from the DUT's UT port to
// the tester's `tester_port`, else nullopt. Untagged IPv4, unfragmented — the
// shape of every reply to a request this file builds.
std::optional<std::vector<std::uint8_t>> utReplyPayload(const std::uint8_t *frame, std::size_t n,
                                                        std::uint32_t dut_ip_be,
                                                        std::uint32_t tester_ip_be,
                                                        std::uint16_t tester_port) {
    constexpr std::size_t kEth = 14;
    if (n < kEth + 20 || frame[12] != 0x08 || frame[13] != 0x00) {
        return std::nullopt;
    }
    const std::uint8_t *ip = frame + kEth;
    const std::size_t ihl = static_cast<std::size_t>(ip[0] & 0x0FU) * 4U;
    if ((ip[0] >> 4) != 4 || ihl < 20 || ip[9] != 17 || n < kEth + ihl + 8 ||
        ((ip[6] & 0x3FU) | ip[7]) != 0) {  // MF set or a non-zero offset: a fragment
        return std::nullopt;
    }
    std::uint32_t src = 0;
    std::uint32_t dst = 0;
    std::memcpy(&src, ip + 12, 4);
    std::memcpy(&dst, ip + 16, 4);
    const std::uint8_t *udp = ip + ihl;
    const auto be16 = [](const std::uint8_t *p) {
        return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
    };
    if (src != dut_ip_be || dst != tester_ip_be || be16(udp) != ut::kPort ||
        be16(udp + 2) != tester_port) {
        return std::nullopt;
    }
    const std::size_t udp_len = be16(udp + 4);
    if (udp_len < 8 || kEth + ihl + udp_len > n) {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>(udp + 8, udp + udp_len);
}

// Wait on `tap` until `timeout_ms` for the reply correlated with `request`
// (<opcode|0x80> <req_id>). Returns its status byte, or nullopt on timeout.
std::optional<std::uint8_t> awaitUtReply(int tap, const std::vector<std::uint8_t> &request,
                                         std::uint32_t dut_ip_be, std::uint32_t tester_ip_be,
                                         std::uint16_t tester_port, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    std::uint8_t buf[2048];
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            return std::nullopt;
        }
        pollfd pfd{tap, POLLIN, 0};
        if (::poll(&pfd, 1, static_cast<int>(left.count())) <= 0) {
            continue;  // timeout re-checks the deadline; EINTR retries
        }
        sockaddr_ll from{};
        socklen_t fromlen = sizeof(from);
        const ssize_t n = ::recvfrom(tap, buf, sizeof(buf), MSG_DONTWAIT,
                                     reinterpret_cast<sockaddr *>(&from), &fromlen);
        if (n <= 0 || from.sll_pkttype == PACKET_OUTGOING) {
            continue;  // our own request leaving, or nothing after all
        }
        const auto payload = utReplyPayload(buf, static_cast<std::size_t>(n), dut_ip_be,
                                            tester_ip_be, tester_port);
        if (payload && payload->size() >= 3 &&
            (*payload)[0] == (request[0] | ut::kResponseBit) && (*payload)[1] == request[1]) {
            return (*payload)[2];
        }
    }
}

}  // namespace

std::uint8_t nextUtReqId() {
    static std::atomic<unsigned int> counter{0};
    return static_cast<std::uint8_t>(counter.fetch_add(1U, std::memory_order_relaxed) % 255U + 1U);
}

std::vector<std::uint8_t> buildGetReceivedUdpRequest(
    std::uint8_t  req_id,
    std::uint16_t listen_port,
    std::uint32_t expected_dst_ip_be) {
    std::vector<std::uint8_t> req;
    req.reserve(8);
    req.push_back(static_cast<std::uint8_t>(ut::OpGetReceivedUdp));
    req.push_back(req_id);
    appendBe16(req, listen_port);
    appendIpv4Be(req, expected_dst_ip_be);
    return req;
}

std::vector<std::uint8_t> buildTriggerSendUdpRequest(
    std::uint8_t        req_id,
    std::uint16_t       src_port,
    std::uint32_t       dst_ip_be,
    std::uint16_t       dst_port,
    const std::uint8_t *payload,
    std::uint16_t       payload_len,
    std::uint32_t       src_ip_override_be) {
    // Clamp to kMaxPayload so a caller-bug-oversize buffer doesn't
    // silently bloat the UT datagram past the tc8-dut parser's bound.
    const std::uint16_t effective_len =
        (payload_len > ut::kMaxPayload) ? ut::kMaxPayload : payload_len;

    const bool emit_override_trailer = (src_ip_override_be != 0U);

    std::vector<std::uint8_t> req;
    req.reserve(12U + effective_len + (emit_override_trailer ? 4U : 0U));
    req.push_back(static_cast<std::uint8_t>(ut::OpTriggerSendUdp));
    req.push_back(req_id);
    appendBe16(req, src_port);
    appendIpv4Be(req, dst_ip_be);
    appendBe16(req, dst_port);
    appendBe16(req, effective_len);
    if (payload != nullptr && effective_len > 0) {
        req.insert(req.end(), payload, payload + effective_len);
    }
    // Append-only trailer: tc8-dut treats absence as "no override".
    // Skipping the trailer for override==0 keeps legacy FRAGMENTS_05 /
    // UI_01..06 callers byte-identical on the wire.
    if (emit_override_trailer) {
        appendIpv4Be(req, src_ip_override_be);
    }
    return req;
}

std::vector<std::uint8_t> buildOpenTcpSocketPassiveRequest(
    std::uint8_t  req_id,
    std::uint16_t local_port) {
    std::vector<std::uint8_t> req;
    req.reserve(5);
    req.push_back(static_cast<std::uint8_t>(ut::OpOpenTcpSocket));
    req.push_back(req_id);
    req.push_back(ut::kSocketTypePassive);
    appendBe16(req, local_port);
    return req;
}

std::vector<std::uint8_t> buildOpenTcpSocketActiveRequest(
    std::uint8_t  req_id,
    std::uint16_t local_port,
    std::uint32_t remote_ip_be,
    std::uint16_t remote_port) {
    std::vector<std::uint8_t> req;
    req.reserve(11);
    req.push_back(static_cast<std::uint8_t>(ut::OpOpenTcpSocket));
    req.push_back(req_id);
    req.push_back(ut::kSocketTypeActive);
    appendBe16(req, local_port);
    appendIpv4Be(req, remote_ip_be);
    appendBe16(req, remote_port);
    return req;
}

std::vector<std::uint8_t> buildCloseTcpSocketRequest(
    std::uint8_t req_id,
    std::uint8_t socket_id) {
    std::vector<std::uint8_t> req;
    req.reserve(3);
    req.push_back(static_cast<std::uint8_t>(ut::OpCloseTcpSocket));
    req.push_back(req_id);
    req.push_back(socket_id);
    return req;
}

std::vector<std::uint8_t> buildQueryTcpEstablishedRequest(
    std::uint8_t req_id,
    std::uint8_t socket_id) {
    std::vector<std::uint8_t> req;
    req.reserve(3);
    req.push_back(static_cast<std::uint8_t>(ut::OpQueryTcpEstablished));
    req.push_back(req_id);
    req.push_back(socket_id);
    return req;
}

std::vector<std::uint8_t> buildQueryTcpInfoRequest(
    std::uint8_t req_id,
    std::uint8_t socket_id) {
    std::vector<std::uint8_t> req;
    req.reserve(3);
    req.push_back(static_cast<std::uint8_t>(ut::OpQueryTcpInfo));
    req.push_back(req_id);
    req.push_back(socket_id);
    return req;
}

std::vector<std::uint8_t> buildSendTcpDataRequest(
    std::uint8_t        req_id,
    std::uint8_t        socket_id,
    const std::uint8_t *payload,
    std::uint16_t       payload_len) {
    const std::uint16_t effective_len =
        (payload_len > ut::kMaxPayload) ? ut::kMaxPayload : payload_len;
    std::vector<std::uint8_t> req;
    req.reserve(5U + effective_len);
    req.push_back(static_cast<std::uint8_t>(ut::OpSendTcpData));
    req.push_back(req_id);
    req.push_back(socket_id);
    appendBe16(req, effective_len);
    if (payload != nullptr && effective_len > 0) {
        req.insert(req.end(), payload, payload + effective_len);
    }
    return req;
}

std::vector<std::uint8_t> buildReceiveTcpDataRequest(
    std::uint8_t  req_id,
    std::uint8_t  socket_id,
    std::uint16_t expected_len,
    std::uint16_t timeout_ms) {
    const std::uint16_t effective_len =
        (expected_len > ut::kMaxPayload) ? ut::kMaxPayload : expected_len;
    std::vector<std::uint8_t> req;
    req.reserve(7);
    req.push_back(static_cast<std::uint8_t>(ut::OpReceiveTcpData));
    req.push_back(req_id);
    req.push_back(socket_id);
    appendBe16(req, effective_len);
    appendBe16(req, timeout_ms);
    return req;
}

std::vector<std::uint8_t> buildReceiveTcpDataOobRequest(
    std::uint8_t  req_id,
    std::uint8_t  socket_id,
    std::uint16_t expected_len,
    std::uint16_t timeout_ms) {
    const std::uint16_t effective_len =
        (expected_len > ut::kMaxPayload) ? ut::kMaxPayload : expected_len;
    std::vector<std::uint8_t> req;
    req.reserve(7);
    req.push_back(static_cast<std::uint8_t>(ut::OpReceiveTcpDataOob));
    req.push_back(req_id);
    req.push_back(socket_id);
    appendBe16(req, effective_len);
    appendBe16(req, timeout_ms);
    return req;
}

std::vector<std::uint8_t> buildShutdownTcpSocketWrRequest(
    std::uint8_t req_id,
    std::uint8_t socket_id) {
    std::vector<std::uint8_t> req;
    req.reserve(3);
    req.push_back(static_cast<std::uint8_t>(ut::OpShutdownTcpSocketWr));
    req.push_back(req_id);
    req.push_back(socket_id);
    return req;
}

std::vector<std::uint8_t> buildAbortTcpSocketRequest(
    std::uint8_t req_id,
    std::uint8_t socket_id) {
    std::vector<std::uint8_t> req;
    req.reserve(3);
    req.push_back(static_cast<std::uint8_t>(ut::OpAbortTcpSocket));
    req.push_back(req_id);
    req.push_back(socket_id);
    return req;
}

std::vector<std::uint8_t> buildSendTcpDataPatternRequest(
    std::uint8_t  req_id,
    std::uint8_t  socket_id,
    std::uint8_t  pattern,
    std::uint16_t total_len) {
    std::vector<std::uint8_t> req;
    req.reserve(6);
    req.push_back(static_cast<std::uint8_t>(ut::OpSendTcpDataPattern));
    req.push_back(req_id);
    req.push_back(socket_id);
    req.push_back(pattern);
    appendBe16(req, total_len);
    return req;
}

std::vector<std::uint8_t> buildStartLLAutoconfRequest(
    std::uint8_t  req_id,
    std::uint16_t dhcp_timeout_ms,
    std::uint16_t probe_wait_ms,
    std::uint16_t probe_min_ms,
    std::uint16_t probe_max_ms,
    std::uint16_t announce_wait_ms,
    std::uint16_t announce_interval_ms,
    std::uint16_t rate_limit_interval_ms) {
    std::vector<std::uint8_t> req;
    req.reserve(16);
    req.push_back(static_cast<std::uint8_t>(ut::OpStartLLAutoconf));
    req.push_back(req_id);
    appendBe16(req, dhcp_timeout_ms);
    appendBe16(req, probe_wait_ms);
    appendBe16(req, probe_min_ms);
    appendBe16(req, probe_max_ms);
    appendBe16(req, announce_wait_ms);
    appendBe16(req, announce_interval_ms);
    appendBe16(req, rate_limit_interval_ms);
    return req;
}

std::vector<std::uint8_t> buildQueryLLAddressRequest(
    std::uint8_t req_id) {
    std::vector<std::uint8_t> req;
    req.reserve(2);
    req.push_back(static_cast<std::uint8_t>(ut::OpQueryLLAddress));
    req.push_back(req_id);
    return req;
}

std::vector<std::uint8_t> buildAbortLLAutoconfRequest(
    std::uint8_t req_id) {
    std::vector<std::uint8_t> req;
    req.reserve(2);
    req.push_back(static_cast<std::uint8_t>(ut::OpAbortLLAutoconf));
    req.push_back(req_id);
    return req;
}

std::vector<std::uint8_t> buildStartDhcpClientRequest(
    std::uint8_t  req_id,
    std::uint16_t offer_wait_ms,
    std::uint16_t ack_wait_ms,
    std::uint8_t  retry_count,
    std::uint16_t retry_interval_ms,
    std::uint16_t nak_to_discover_min_ms,
    std::uint16_t nak_to_discover_max_ms,
    std::uint16_t arp_probe_listen_ms,
    std::uint16_t decline_to_discover_min_ms,
    std::uint16_t decline_to_discover_max_ms,
    std::uint16_t retx_first_ms,
    std::uint16_t retx_cap_ms,
    std::uint16_t retx_jitter_ms,
    std::uint8_t  iface_index,
    std::uint8_t  flavor) {
    std::vector<std::uint8_t> req;
    req.reserve(27);
    req.push_back(static_cast<std::uint8_t>(ut::OpStartDhcpClient));
    req.push_back(req_id);
    appendBe16(req, offer_wait_ms);
    appendBe16(req, ack_wait_ms);
    req.push_back(retry_count);
    appendBe16(req, retry_interval_ms);
    appendBe16(req, nak_to_discover_min_ms);
    appendBe16(req, nak_to_discover_max_ms);
    appendBe16(req, arp_probe_listen_ms);
    appendBe16(req, decline_to_discover_min_ms);
    appendBe16(req, decline_to_discover_max_ms);
    appendBe16(req, retx_first_ms);
    appendBe16(req, retx_cap_ms);
    appendBe16(req, retx_jitter_ms);
    req.push_back(iface_index);
    // Trailing flavor byte at param offset 24 (the DUT reader's n >= 25 gate).
    // 0 = kDhcpFlavorNone, so a positive request (no flavor) stays conformant;
    // a _neg passes a kDhcpFlavor* byte to arm exactly one firmware mutant.
    req.push_back(flavor);
    return req;
}

std::vector<std::uint8_t> buildQueryDhcpLeaseRequest(std::uint8_t req_id) {
    std::vector<std::uint8_t> req;
    req.reserve(2);
    req.push_back(static_cast<std::uint8_t>(ut::OpQueryDhcpLease));
    req.push_back(req_id);
    return req;
}

std::vector<std::uint8_t> buildAbortDhcpClientRequest(std::uint8_t req_id) {
    std::vector<std::uint8_t> req;
    req.reserve(2);
    req.push_back(static_cast<std::uint8_t>(ut::OpAbortDhcpClient));
    req.push_back(req_id);
    return req;
}

std::vector<std::uint8_t> buildCreateUdpReceivePortsRequest(
    std::uint8_t req_id,
    std::uint8_t count) {
    std::vector<std::uint8_t> req;
    req.reserve(3);
    req.push_back(static_cast<std::uint8_t>(ut::OpCreateUdpReceivePorts));
    req.push_back(req_id);
    req.push_back(count);
    return req;
}

std::vector<std::uint8_t> buildPingRequest(std::uint8_t req_id) {
    std::vector<std::uint8_t> req;
    req.reserve(2);
    req.push_back(static_cast<std::uint8_t>(ut::OpPing));
    req.push_back(req_id);
    return req;
}

std::vector<std::uint8_t> buildQueryCapabilitiesRequest(std::uint8_t req_id) {
    std::vector<std::uint8_t> req;
    req.reserve(2);
    req.push_back(static_cast<std::uint8_t>(ut::OpQueryCapabilities));
    req.push_back(req_id);
    return req;
}

std::vector<std::uint8_t> buildConditionArpCacheRequest(
    std::uint8_t  req_id,
    std::uint8_t  action,
    std::uint16_t param) {
    std::vector<std::uint8_t> req;
    req.reserve(5);
    req.push_back(static_cast<std::uint8_t>(ut::OpConditionArpCache));
    req.push_back(req_id);
    req.push_back(action);
    appendBe16(req, param);
    return req;
}

std::vector<std::uint8_t> buildArpAddStaticRequest(
    std::uint8_t req_id,
    std::uint32_t entry_ip_be,
    const std::array<std::uint8_t, 6> &entry_mac) {
    auto req = buildConditionArpCacheRequest(req_id, ut::kArpConditionAddStatic, 0);
    appendIpv4Be(req, entry_ip_be);
    req.insert(req.end(), entry_mac.begin(), entry_mac.end());
    return req;
}

std::vector<std::uint8_t> buildArpRemoveStaticRequest(
    std::uint8_t req_id,
    std::uint32_t entry_ip_be) {
    auto req = buildConditionArpCacheRequest(req_id, ut::kArpConditionRemoveStatic, 0);
    appendIpv4Be(req, entry_ip_be);
    return req;
}

std::vector<std::uint8_t> buildSetFlavorRequest(
    std::uint8_t opcode,
    std::uint8_t req_id,
    std::uint8_t flavor) {
    std::vector<std::uint8_t> req;
    req.reserve(3);
    req.push_back(opcode);
    req.push_back(req_id);
    req.push_back(flavor);
    return req;
}

std::vector<std::uint8_t> buildStartLLAutoconfBuggyRequest(
    std::uint8_t  req_id,
    std::uint16_t dhcp_timeout_ms,
    std::uint16_t probe_wait_ms,
    std::uint16_t probe_min_ms,
    std::uint16_t probe_max_ms,
    std::uint16_t announce_wait_ms,
    std::uint16_t announce_interval_ms,
    std::uint16_t rate_limit_interval_ms,
    std::uint8_t  flavor) {
    std::vector<std::uint8_t> req;
    req.reserve(17);
    req.push_back(static_cast<std::uint8_t>(ut::OpStartLLAutoconfBuggy));
    req.push_back(req_id);
    appendBe16(req, dhcp_timeout_ms);
    appendBe16(req, probe_wait_ms);
    appendBe16(req, probe_min_ms);
    appendBe16(req, probe_max_ms);
    appendBe16(req, announce_wait_ms);
    appendBe16(req, announce_interval_ms);
    appendBe16(req, rate_limit_interval_ms);
    req.push_back(flavor);
    return req;
}

namespace {

// Shared SOCK_DGRAM UT round trip for the probe family (OpPing /
// OpQueryCapabilities): optional source bind, receive timeout, one
// request out, one response in. Returns the response byte count
// (>= 3, header validated against `req`'s opcode/req_id) or -1 on
// any transport failure. The caller interprets the status byte —
// kStatusUnknownOpcode is a meaningful answer for the capability
// probe, not a transport failure.
ssize_t dgramUtRoundTrip(std::uint32_t dut_ip_be,
                         std::uint16_t dut_port,
                         int timeout_ms,
                         std::uint32_t src_ip_be,
                         const std::vector<std::uint8_t> &req,
                         std::uint8_t *resp,
                         std::size_t resp_len) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    if (src_ip_be != 0U) {
        sockaddr_in src{};
        src.sin_family      = AF_INET;
        src.sin_port        = 0;  // ephemeral
        src.sin_addr.s_addr = src_ip_be;
        if (::bind(fd, reinterpret_cast<const sockaddr *>(&src),
                   sizeof(src)) < 0) {
            ::close(fd);
            return -1;
        }
    }

    timeval tv{};
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in dst{};
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(dut_port);
    dst.sin_addr.s_addr = dut_ip_be;

    if (::sendto(fd, req.data(), req.size(), 0,
                 reinterpret_cast<const sockaddr *>(&dst),
                 sizeof(dst)) < 0) {
        ::close(fd);
        return -1;
    }

    const ssize_t n = ::recv(fd, resp, resp_len, 0);
    ::close(fd);
    if (n < 3 || resp[0] != (req[0] | ut::kResponseBit) ||
        resp[1] != req[1]) {
        return -1;
    }
    return n;
}

}  // namespace

std::optional<UtPingResult> pingUpperTester(std::uint32_t dut_ip_be,
                                            std::uint16_t dut_port,
                                            int timeout_ms,
                                            std::uint32_t src_ip_be) {
    // Response: <OpPing|0x80> <req_id> <status> <max_opcode>.
    std::uint8_t buf[8] = {};
    const ssize_t n = dgramUtRoundTrip(dut_ip_be, dut_port, timeout_ms,
                                       src_ip_be, buildPingRequest(nextUtReqId()),
                                       buf, sizeof(buf));
    if (n < 4 || buf[2] != ut::kStatusOk) {
        return std::nullopt;
    }
    return UtPingResult{buf[3]};
}

std::optional<UtCapabilities> queryUpperTesterCapabilities(
    std::uint32_t dut_ip_be,
    std::uint16_t dut_port,
    int timeout_ms,
    std::uint32_t src_ip_be) {
    // Response: <0x16|0x80> <req_id> <status> <bitmap_len> <bitmap[]>.
    // 16 bytes covers a 12-byte bitmap (opcodes through 0x5F) — well
    // past kMaxProtocolOpcode growth before this buffer needs a bump.
    std::uint8_t buf[16] = {};
    const ssize_t n = dgramUtRoundTrip(
        dut_ip_be, dut_port, timeout_ms, src_ip_be,
        buildQueryCapabilitiesRequest(nextUtReqId()), buf, sizeof(buf));
    if (n < 3) {
        return std::nullopt;
    }
    if (buf[2] == ut::kStatusUnknownOpcode) {
        // Pre-0x16 firmware — a meaningful answer, not a failure.
        return UtCapabilities{};
    }
    if (buf[2] != ut::kStatusOk || n < 4) {
        return std::nullopt;
    }
    const std::size_t bitmap_len = buf[3];
    if (static_cast<std::size_t>(n) < 4 + bitmap_len) {
        return std::nullopt;
    }
    UtCapabilities caps;
    caps.supported = true;
    caps.bitmap.assign(buf + 4, buf + 4 + bitmap_len);
    return caps;
}

std::optional<UtReply> upperTesterRoundTrip(std::uint32_t dut_ip_be,
                                            const std::vector<std::uint8_t> &request,
                                            std::uint16_t dut_port, int timeout_ms,
                                            std::uint32_t src_ip_be) {
    std::uint8_t buf[2048];
    const ssize_t n =
        dgramUtRoundTrip(dut_ip_be, dut_port, timeout_ms, src_ip_be, request, buf, sizeof(buf));
    if (n < 3) {
        return std::nullopt;  // transport failure / uncorrelated reply
    }
    UtReply r;
    r.status = buf[2];
    r.data.assign(buf + 3, buf + n);  // bytes after <opcode|0x80> <req_id> <status>
    return r;
}

int sendUpperTesterRequest(std::string_view iface,
                           std::uint32_t tester_ip_be,
                           std::uint32_t dut_ip_be,
                           const std::array<std::uint8_t, 6> &dut_mac,
                           std::uint16_t tester_src_port,
                           const std::vector<std::uint8_t> &ut_payload) {
    const auto udp = buildUdpDatagram(tester_ip_be, dut_ip_be,
                                       tester_src_port, ut::kPort,
                                       ut_payload.data(), ut_payload.size());

    Ipv4FrameSpec spec{};
    spec.dst_mac     = dut_mac;
    spec.src_ip      = tester_ip_be;
    spec.dst_ip      = dut_ip_be;
    spec.ip_protocol = kIpProtoUdp;
    const auto frame = buildIpv4Frame(spec, udp);
    return sendRawEthernet(frame, iface);
}

int sendUpperTesterRequestAwaited(std::string_view iface,
                                  std::uint32_t tester_ip_be,
                                  std::uint32_t dut_ip_be,
                                  const std::array<std::uint8_t, 6> &dut_mac,
                                  std::uint16_t tester_src_port,
                                  const std::vector<std::uint8_t> &ut_payload,
                                  int timeout_ms,
                                  std::string_view stimulus_name) {
    if (ut_payload.size() < 2) {
        return -4;  // no opcode/req_id to correlate a reply against
    }
    // The reply is HEARD at L2, not received on a UDP socket. A kernel socket gets
    // only frames addressed to this interface's own MAC, and the DUT addresses its
    // reply by whatever its ARP table holds for the tester — which, by the time a
    // §4.2 case conditions anything, is routinely a MAC the case injected
    // (MAC-ADDR1) or installed as a static entry. Measured on the wire (the first
    // static-entry run): the acknowledgement of AddStatic went to 02:00:00:00:00:a1,
    // 0.35 ms after the request, and a kernel socket reported "no correlated reply"
    // for a step the capture shows applied. The tap hears it whatever the MAC.
    //
    // The UDP socket is still bound, and for a different reason: when the reply
    // DOES reach this interface's own MAC, an unbound port would make the tester's
    // kernel answer the DUT with ICMP port-unreachable, a frame of the tester's own
    // making on the wire under test. Both are opened BEFORE the send — the DUT
    // answers within ~500 us.
    const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -4;
    }
    sockaddr_in src{};
    src.sin_family      = AF_INET;
    src.sin_port        = htons(tester_src_port);
    src.sin_addr.s_addr = tester_ip_be;
    if (::bind(fd, reinterpret_cast<const sockaddr *>(&src), sizeof(src)) < 0) {
        std::fprintf(stderr, "stimulus: UT await bind(:%u) failed: %s\n",
                     tester_src_port, std::strerror(errno));
        ::close(fd);
        return -4;
    }
    const int tap = openUtReplyTap(iface);
    if (tap < 0) {
        std::fprintf(stderr, "stimulus: UT await tap on '%.*s' failed: %s\n",
                     static_cast<int>(iface.size()), iface.data(), std::strerror(errno));
        ::close(fd);
        return -4;
    }

    const int sent = sendUpperTesterRequest(iface, tester_ip_be, dut_ip_be, dut_mac,
                                            tester_src_port, ut_payload);
    // Correlate on <opcode|kResponseBit> <req_id>, the same rule dgramUtRoundTrip
    // uses. A stray datagram on this port must not be read as our acknowledgement.
    const std::optional<std::uint8_t> heard =
        sent < 0 ? std::nullopt
                 : awaitUtReply(tap, ut_payload, dut_ip_be, tester_ip_be, tester_src_port,
                                timeout_ms);
    ::close(tap);
    ::close(fd);
    if (sent < 0) {
        return sent;
    }
    if (!heard) {
        std::fprintf(stderr,
                     "stimulus: UT opcode 0x%02x got no correlated reply in %d ms"
                     " — the DUT may not have applied it before the next step\n",
                     ut_payload[0], timeout_ms);
        return -4;
    }
    const std::uint8_t status = *heard;
    if (status != ut::kStatusOk) {
        // The DUT answered, and its answer is "I did not do that". Name the
        // stimulus so the verdict points at the step that did not happen instead
        // of at a DUT behaviour nothing ever provoked. The mechanical fallback
        // keeps an unnamed caller honest rather than silent.
        char fallback[32];
        std::snprintf(fallback, sizeof(fallback), "dut_ut_opcode_0x%02x", ut_payload[0]);
        const std::string name =
            stimulus_name.empty() ? std::string(fallback) : std::string(stimulus_name);
        std::fprintf(stderr,
                     "stimulus: UT opcode 0x%02x answered status 0x%02x — the DUT did not "
                     "perform '%s'; the case has no premise and its verdict is downgraded\n",
                     ut_payload[0], status, name.c_str());
        ::tc8::UnperformedStimulus::record(name);
    }
    return status;
}

int emitTriggerSendUdpBoot(std::string_view iface,
                           std::uint32_t tester_ip_be,
                           std::uint32_t dut_ip_be,
                           const std::array<std::uint8_t, 6> &dut_mac,
                           const BootTiming &timing) {
    // Payload content carries no verdict weight (§4.2 guards compare
    // dst_ip + Eth-dst only); a recognisable literal helps pcap readers.
    static constexpr std::uint8_t kPayload[] = {'T', 'C', '8', '-', 'E', 'G',
                                                'R', 'E', 'S', 'S'};

    return runBootCadence(timing, [&](int /*attempt*/) {
        const auto req = buildTriggerSendUdpRequest(
            nextUtReqId(), kEgressBootDutSrcPort,
            tester_ip_be, ut::kDataPort, kPayload,
            static_cast<std::uint16_t>(sizeof(kPayload)));
        return sendUpperTesterRequest(iface, tester_ip_be, dut_ip_be, dut_mac,
                                      ut::kTesterSrcPort, req);
    });
}

int emitConditionArpCache(std::string_view iface,
                          std::uint32_t tester_ip_be,
                          std::uint32_t dut_ip_be,
                          const std::array<std::uint8_t, 6> &dut_mac,
                          std::uint8_t action,
                          std::uint16_t param) {
    const auto req = buildConditionArpCacheRequest(nextUtReqId(), action, param);
    return sendUpperTesterRequest(iface, tester_ip_be, dut_ip_be, dut_mac,
                                  ut::kTesterSrcPort, req);
}

int emitArpAddStatic(std::string_view iface,
                     std::uint32_t tester_ip_be,
                     std::uint32_t dut_ip_be,
                     const std::array<std::uint8_t, 6> &dut_mac,
                     std::uint32_t entry_ip_be,
                     const std::array<std::uint8_t, 6> &entry_mac) {
    return sendUpperTesterRequestAwaited(iface, tester_ip_be, dut_ip_be, dut_mac,
                                         ut::kTesterSrcPort,
                                         buildArpAddStaticRequest(nextUtReqId(), entry_ip_be,
                                                                  entry_mac),
                                         kAwaitedUtTimeoutMs, "dut_arp_static_entry_add");
}

int emitArpRemoveStatic(std::string_view iface,
                        std::uint32_t tester_ip_be,
                        std::uint32_t dut_ip_be,
                        const std::array<std::uint8_t, 6> &dut_mac,
                        std::uint32_t entry_ip_be) {
    return sendUpperTesterRequestAwaited(iface, tester_ip_be, dut_ip_be, dut_mac,
                                         ut::kTesterSrcPort,
                                         buildArpRemoveStaticRequest(nextUtReqId(), entry_ip_be),
                                         kAwaitedUtTimeoutMs, "dut_arp_static_entry_remove");
}

int emitSetEgressFlavor(std::string_view iface,
                        std::uint32_t tester_ip_be,
                        std::uint32_t dut_ip_be,
                        const std::array<std::uint8_t, 6> &dut_mac,
                        std::uint8_t flavor) {
    const auto req = buildSetFlavorRequest(ut::OpSetEgressFlavor, nextUtReqId(), flavor);
    // Named for the ledger: a `_neg` mutant whose fault never armed observes a
    // COMPLIANT DUT and would otherwise report the harness's own self-validation
    // as passed — the false direction that costs the most, since the point of the
    // row is to prove the verdict machinery still fails a wrong expectation.
    return sendUpperTesterRequestAwaited(iface, tester_ip_be, dut_ip_be, dut_mac,
                                  ut::kTesterSrcPort, req, kAwaitedUtTimeoutMs,
                                  "dut_egress_flavor_arm");
}

int emitSetIngressFlavor(std::string_view iface,
                         std::uint32_t tester_ip_be,
                         std::uint32_t dut_ip_be,
                         const std::array<std::uint8_t, 6> &dut_mac,
                         std::uint8_t flavor) {
    const auto req = buildSetFlavorRequest(ut::OpSetIngressFlavor, nextUtReqId(), flavor);
    return sendUpperTesterRequestAwaited(iface, tester_ip_be, dut_ip_be, dut_mac,
                                  ut::kTesterSrcPort, req, kAwaitedUtTimeoutMs,
                                  "dut_ingress_flavor_arm");
}

int emitSetAppFlavor(std::string_view iface,
                     std::uint32_t tester_ip_be,
                     std::uint32_t dut_ip_be,
                     const std::array<std::uint8_t, 6> &dut_mac,
                     std::uint8_t flavor) {
    const auto req = buildSetFlavorRequest(ut::OpSetAppFlavor, nextUtReqId(), flavor);
    return sendUpperTesterRequestAwaited(iface, tester_ip_be, dut_ip_be, dut_mac,
                                  ut::kTesterSrcPort, req, kAwaitedUtTimeoutMs,
                                  "dut_app_flavor_arm");
}

int emitSetEtsFlavor(std::string_view iface,
                     std::uint32_t tester_ip_be,
                     std::uint32_t dut_ip_be,
                     const std::array<std::uint8_t, 6> &dut_mac,
                     std::uint8_t flavor) {
    const auto req = buildSetFlavorRequest(ut::OpSetEtsFlavor, nextUtReqId(), flavor);
    return sendUpperTesterRequestAwaited(iface, tester_ip_be, dut_ip_be, dut_mac,
                                  ut::kTesterSrcPort, req, kAwaitedUtTimeoutMs,
                                  "dut_ets_flavor_arm");
}

}  // namespace tc8::stimulus
