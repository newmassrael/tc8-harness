#include "stimulus/upper_tester_client.h"

#include <algorithm>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

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

}  // namespace

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
    std::uint8_t  iface_index) {
    std::vector<std::uint8_t> req;
    req.reserve(26);
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

std::optional<UtPingResult> pingUpperTester(std::uint32_t dut_ip_be,
                                            std::uint16_t dut_port,
                                            int timeout_ms,
                                            std::uint32_t src_ip_be) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return std::nullopt;
    }

    if (src_ip_be != 0U) {
        sockaddr_in src{};
        src.sin_family      = AF_INET;
        src.sin_port        = 0;  // ephemeral
        src.sin_addr.s_addr = src_ip_be;
        if (::bind(fd, reinterpret_cast<const sockaddr *>(&src),
                   sizeof(src)) < 0) {
            ::close(fd);
            return std::nullopt;
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

    constexpr std::uint8_t kReqId = 0x01;
    const auto req = buildPingRequest(kReqId);
    if (::sendto(fd, req.data(), req.size(), 0,
                 reinterpret_cast<const sockaddr *>(&dst),
                 sizeof(dst)) < 0) {
        ::close(fd);
        return std::nullopt;
    }

    // Response: <OpPing|0x80> <req_id> <status> <max_opcode>.
    std::uint8_t buf[8] = {};
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    ::close(fd);
    if (n < 4 || buf[0] != (ut::OpPing | ut::kResponseBit) ||
        buf[1] != kReqId || buf[2] != ut::kStatusOk) {
        return std::nullopt;
    }
    return UtPingResult{buf[3]};
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

int emitTriggerSendUdpBoot(std::string_view iface,
                           std::uint32_t tester_ip_be,
                           std::uint32_t dut_ip_be,
                           const std::array<std::uint8_t, 6> &dut_mac,
                           const BootTiming &timing) {
    // Payload content carries no verdict weight (§4.2 guards compare
    // dst_ip + Eth-dst only); a recognisable literal helps pcap readers.
    static constexpr std::uint8_t kPayload[] = {'T', 'C', '8', '-', 'E', 'G',
                                                'R', 'E', 'S', 'S'};

    std::this_thread::sleep_for(timing.initial_wait);

    for (int i = 0; i < timing.total_emits; ++i) {
        if (i > 0) {
            std::this_thread::sleep_for(timing.retry_interval);
        }
        const auto req = buildTriggerSendUdpRequest(
            static_cast<std::uint8_t>(1 + i), kEgressBootDutSrcPort,
            tester_ip_be, ut::kDataPort, kPayload,
            static_cast<std::uint16_t>(sizeof(kPayload)));
        const int rc = sendUpperTesterRequest(iface, tester_ip_be, dut_ip_be,
                                              dut_mac,
                                              kEgressBootTesterSrcPort, req);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

}  // namespace tc8::stimulus
