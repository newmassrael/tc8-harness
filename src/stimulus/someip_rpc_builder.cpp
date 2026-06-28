#include "stimulus/someip_rpc_builder.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "someip/wire.h"
#include "stimulus/iface_addr.h"
#include "stimulus/udp_emit.h"

namespace tc8::stimulus {

std::vector<std::uint8_t> buildMethodRequest(const SomeIpRpcMessage &t) {
    std::vector<std::uint8_t> b;
    b.reserve(16 + t.payload.size());
    someip::Header h;
    h.service_id = t.service_id;
    h.method_id = t.method_id;
    // Length covers everything from Request ID through end of payload. The
    // optional override lets cases drive deliberate header/payload mismatches
    // (§5.1.6 ETS_001/_002 PRS_SOMEIP_00099 axis).
    h.length = t.length_override.value_or(static_cast<std::uint32_t>(8 + t.payload.size()));
    h.client_id = t.client_id;
    h.session_id = t.session_id;
    h.protocol_version = t.protocol_version;
    h.interface_version = t.interface_version;
    h.message_type = t.message_type_override.value_or(static_cast<std::uint8_t>(t.message_type));
    h.return_code = t.return_code_override.value_or(static_cast<std::uint8_t>(t.return_code));
    someip::appendHeader(b, h);
    b.insert(b.end(), t.payload.begin(), t.payload.end());
    return b;
}

// Tester server-role replies reuse the request header core; only the
// message_type differs (PRS_SOMEIP_00701). Taken by value so the forced
// message_type does not mutate the caller's target. return_code is left as
// the caller set it (PRS_SOMEIP_00757 governs the allowed values per type).
std::vector<std::uint8_t> buildMethodResponse(SomeIpRpcMessage t) {
    t.message_type = someip::MessageType::RESPONSE;
    return buildMethodRequest(t);
}

std::vector<std::uint8_t> buildMethodError(SomeIpRpcMessage t) {
    t.message_type = someip::MessageType::ERROR;
    return buildMethodRequest(t);
}

int emitMethodReply(std::string_view iface, const std::vector<std::uint8_t> &reply,
                    std::uint16_t service_src_port, const MethodEndpoint &client_dest) {
    // Server reply: source = the tester's service port (not ephemeral), dest =
    // the DUT client endpoint. Generic UDP mechanics live in sendUdpUnicast.
    return sendUdpUnicast(reply, iface, service_src_port, client_dest.ipv4_be, client_dest.port);
}

namespace {

int requestOnce(const SomeIpRpcMessage &target, std::uint16_t session_id, std::string_view iface,
                const MethodEndpoint &dest) {
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: socket() failed: %s\n", std::strerror(errno));
        return -1;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr, "stimulus: interface '%.*s' has no IPv4 address — "
                             "cannot bind tester source for method request\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return -2;
    }

    // Ephemeral source port — vsomeip accepts any source port for method
    // requests (unlike SD, which gates on source-port = SD port). The
    // kernel picks a free port via bind(port=0).
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: bind(method request ephemeral) failed: %s\n", std::strerror(errno));
        ::close(sock);
        return -3;
    }

    SomeIpRpcMessage t = target;
    t.session_id = session_id;
    const auto datagram = buildMethodRequest(t);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dest.port);
    dst.sin_addr.s_addr = dest.ipv4_be;

    const ssize_t n =
        ::sendto(sock, datagram.data(), datagram.size(), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    const int saved_errno = errno;
    ::close(sock);
    if (n < 0 || static_cast<std::size_t>(n) != datagram.size()) {
        std::fprintf(stderr, "stimulus: sendto(method request dut:%u) failed: %s (sent=%zd of %zu)\n", dest.port,
                     std::strerror(saved_errno), n, datagram.size());
        return -4;
    }
    return 0;
}

}  // namespace

int emitMethodRequestAfter(std::string_view iface, const SomeIpRpcMessage &target,
                           const MethodRequestTiming &timing, const MethodEndpoint &dest) {
    std::this_thread::sleep_for(timing.pre_emit_wait);

    for (int i = 0; i < timing.total_emits; ++i) {
        if (i > 0) {
            std::this_thread::sleep_for(timing.retry_interval);
        }
        const std::uint16_t session_id = static_cast<std::uint16_t>(target.session_id + i);
        const int rc = requestOnce(target, session_id, iface, dest);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

namespace {

int requestOnceTcp(const SomeIpRpcMessage &target, std::uint16_t session_id, std::string_view iface,
                   const MethodEndpoint &dest, std::chrono::milliseconds linger) {
    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: tcp socket() failed: %s\n", std::strerror(errno));
        return -1;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr, "stimulus: interface '%.*s' has no IPv4 address — "
                             "cannot bind tester source for tcp method request\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return -2;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: tcp bind(ephemeral) failed: %s\n", std::strerror(errno));
        ::close(sock);
        return -3;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dest.port);
    dst.sin_addr.s_addr = dest.ipv4_be;

    if (::connect(sock, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)) < 0) {
        std::fprintf(stderr, "stimulus: tcp connect(dut:%u) failed: %s\n",
                     dest.port, std::strerror(errno));
        ::close(sock);
        return -4;
    }

    SomeIpRpcMessage t = target;
    t.session_id = session_id;
    const auto datagram = buildMethodRequest(t);

    const ssize_t n = ::send(sock, datagram.data(), datagram.size(), 0);
    if (n < 0 || static_cast<std::size_t>(n) != datagram.size()) {
        const int saved_errno = errno;
        std::fprintf(stderr, "stimulus: tcp send(method request dut:%u) failed: %s (sent=%zd of %zu)\n",
                     dest.port, std::strerror(saved_errno), n, datagram.size());
        ::close(sock);
        return -5;
    }

    // Dwell so vsomeip's tcp_server_endpoint can handle the Request and
    // queue a Response back on the same socket before close() tears
    // down the connection. close() RST's an unread receive buffer, so
    // we don't need to read() the response — pcap captures it on the
    // wire regardless.
    std::this_thread::sleep_for(linger);
    ::close(sock);
    return 0;
}

}  // namespace

int emitMethodRequestTcpAfter(std::string_view iface, const SomeIpRpcMessage &target,
                              const MethodRequestTiming &timing, const MethodEndpoint &dest,
                              const MethodRequestTcpDwell &dwell) {
    std::this_thread::sleep_for(timing.pre_emit_wait);

    for (int i = 0; i < timing.total_emits; ++i) {
        if (i > 0) {
            std::this_thread::sleep_for(timing.retry_interval);
        }
        const std::uint16_t session_id = static_cast<std::uint16_t>(target.session_id + i);
        const int rc = requestOnceTcp(target, session_id, iface, dest, dwell.linger);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

int emitMethodRequestTcpAndHold(std::string_view iface, const SomeIpRpcMessage &target,
                                const MethodEndpoint &dest,
                                std::chrono::milliseconds pre_emit_wait,
                                std::chrono::milliseconds dwell_after_send) {
    std::this_thread::sleep_for(pre_emit_wait);

    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: tcp hold socket() failed: %s\n", std::strerror(errno));
        return -1;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr, "stimulus: interface '%.*s' has no IPv4 address — "
                             "cannot bind tester source for tcp hold\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return -2;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: tcp hold bind(ephemeral) failed: %s\n", std::strerror(errno));
        ::close(sock);
        return -3;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dest.port);
    dst.sin_addr.s_addr = dest.ipv4_be;

    if (::connect(sock, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)) < 0) {
        std::fprintf(stderr, "stimulus: tcp hold connect(dut:%u) failed: %s\n",
                     dest.port, std::strerror(errno));
        ::close(sock);
        return -4;
    }

    const auto datagram = buildMethodRequest(target);
    const ssize_t n = ::send(sock, datagram.data(), datagram.size(), 0);
    if (n < 0 || static_cast<std::size_t>(n) != datagram.size()) {
        const int saved_errno = errno;
        std::fprintf(stderr, "stimulus: tcp hold send(dut:%u) failed: %s (sent=%zd of %zu)\n",
                     dest.port, std::strerror(saved_errno), n, datagram.size());
        ::close(sock);
        return -5;
    }

    // Hold the socket open across the dwell so vsomeip's tcp_server_endpoint
    // delivers the Response on the same connection and the kernel records
    // the resulting TCP state. The fd stays alive on return so the caller
    // can drive a follow-up stimulus (e.g. resetInterface UDP) and later
    // verdict the connection state via getTcpPeerStateAndClose.
    std::this_thread::sleep_for(dwell_after_send);
    return sock;
}

namespace {

// Concatenates each target's wire bytes (SOME/IP header + payload)
// into a single buffer. Per-target Length headers stay self-
// consistent (or honour each target's own length_override) so the
// receiving side can walk the buffer one message at a time.
std::vector<std::uint8_t> buildBundledMethodRequests(
    const std::vector<SomeIpRpcMessage> &targets) {
    std::vector<std::uint8_t> bundle;
    for (const auto &t : targets) {
        const auto one = buildMethodRequest(t);
        bundle.insert(bundle.end(), one.begin(), one.end());
    }
    return bundle;
}

}  // namespace

int emitBundledMethodRequestsUdp(std::string_view iface,
                                 const std::vector<SomeIpRpcMessage> &targets,
                                 std::chrono::milliseconds pre_emit_wait,
                                 const MethodEndpoint &dest) {
    std::this_thread::sleep_for(pre_emit_wait);

    if (targets.empty()) {
        return 0;
    }

    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: bundled udp socket() failed: %s\n", std::strerror(errno));
        return -1;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr, "stimulus: interface '%.*s' has no IPv4 address — "
                             "cannot bind tester source for bundled udp\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return -2;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: bundled udp bind(ephemeral) failed: %s\n",
                     std::strerror(errno));
        ::close(sock);
        return -3;
    }

    const auto bundle = buildBundledMethodRequests(targets);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dest.port);
    dst.sin_addr.s_addr = dest.ipv4_be;

    const ssize_t n = ::sendto(sock, bundle.data(), bundle.size(), 0,
                               reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    const int saved_errno = errno;
    ::close(sock);
    if (n < 0 || static_cast<std::size_t>(n) != bundle.size()) {
        std::fprintf(stderr, "stimulus: bundled udp sendto(dut:%u) failed: %s (sent=%zd of %zu)\n",
                     dest.port, std::strerror(saved_errno), n, bundle.size());
        return -4;
    }
    return 0;
}

int emitBundledMethodRequestsTcp(std::string_view iface,
                                 const std::vector<SomeIpRpcMessage> &targets,
                                 std::chrono::milliseconds pre_emit_wait,
                                 const MethodEndpoint &dest,
                                 std::chrono::milliseconds linger) {
    std::this_thread::sleep_for(pre_emit_wait);

    if (targets.empty()) {
        return 0;
    }

    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: bundled tcp socket() failed: %s\n", std::strerror(errno));
        return -1;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr, "stimulus: interface '%.*s' has no IPv4 address — "
                             "cannot bind tester source for bundled tcp\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return -2;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: bundled tcp bind(ephemeral) failed: %s\n",
                     std::strerror(errno));
        ::close(sock);
        return -3;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dest.port);
    dst.sin_addr.s_addr = dest.ipv4_be;

    if (::connect(sock, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)) < 0) {
        std::fprintf(stderr, "stimulus: bundled tcp connect(dut:%u) failed: %s\n",
                     dest.port, std::strerror(errno));
        ::close(sock);
        return -4;
    }

    const auto bundle = buildBundledMethodRequests(targets);
    const ssize_t n = ::send(sock, bundle.data(), bundle.size(), 0);
    if (n < 0 || static_cast<std::size_t>(n) != bundle.size()) {
        const int saved_errno = errno;
        std::fprintf(stderr, "stimulus: bundled tcp send(dut:%u) failed: %s (sent=%zd of %zu)\n",
                     dest.port, std::strerror(saved_errno), n, bundle.size());
        ::close(sock);
        return -5;
    }

    // Hold the socket open across the dwell so vsomeip's
    // tcp_server_endpoint can walk the bundle, dispatch each Request
    // and queue 3 Responses back on the same connection before
    // close() RSTs the link.
    std::this_thread::sleep_for(linger);
    ::close(sock);
    return 0;
}

int getTcpPeerStateAndClose(int fd, std::uint8_t *out_tcpi_state) {
    if (out_tcpi_state != nullptr) {
        *out_tcpi_state = 0;
    }
    if (fd < 0) {
        return -1;
    }

    tcp_info info{};
    socklen_t info_len = sizeof(info);
    const int rc = ::getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &info_len);
    const int saved_errno = errno;
    ::close(fd);
    if (rc < 0) {
        std::fprintf(stderr, "stimulus: getsockopt(TCP_INFO) failed: %s\n",
                     std::strerror(saved_errno));
        return -2;
    }
    if (out_tcpi_state != nullptr) {
        *out_tcpi_state = info.tcpi_state;
    }
    return 0;
}

int openTcpListener(std::string_view iface, std::uint16_t port) {
    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: tcp listen socket() failed: %s\n",
                     std::strerror(errno));
        return -1;
    }

    const int reuse = 1;
    if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::fprintf(stderr, "stimulus: tcp listen SO_REUSEADDR failed: %s\n",
                     std::strerror(errno));
        ::close(sock);
        return -2;
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface);
    if (if_addr == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — "
                     "cannot bind tcp listener\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return -3;
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = if_addr;
    addr.sin_port        = htons(port);
    if (::bind(sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        std::fprintf(stderr, "stimulus: tcp listen bind(%u) failed: %s\n",
                     port, std::strerror(errno));
        ::close(sock);
        return -4;
    }
    if (::listen(sock, 1) < 0) {
        std::fprintf(stderr, "stimulus: tcp listen(%u) failed: %s\n",
                     port, std::strerror(errno));
        ::close(sock);
        return -5;
    }
    return sock;
}

int acceptTcpOnce(int listen_fd, std::chrono::milliseconds timeout) {
    if (listen_fd < 0) {
        return -1;
    }
    pollfd pfd{};
    pfd.fd     = listen_fd;
    pfd.events = POLLIN;
    const int rc = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
    if (rc < 0) {
        std::fprintf(stderr, "stimulus: tcp accept poll failed: %s\n",
                     std::strerror(errno));
        return -2;
    }
    if (rc == 0) {
        return 0;  // Timed out — no inbound connection.
    }
    sockaddr_in peer{};
    socklen_t   peer_len = sizeof(peer);
    const int   accepted = ::accept(listen_fd, reinterpret_cast<sockaddr *>(&peer), &peer_len);
    if (accepted < 0) {
        std::fprintf(stderr, "stimulus: tcp accept failed: %s\n",
                     std::strerror(errno));
        return -3;
    }
    ::close(accepted);
    return 1;
}

}  // namespace tc8::stimulus
