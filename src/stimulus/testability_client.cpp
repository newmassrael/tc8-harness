#include "stimulus/testability_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstring>

namespace tc8::stimulus {

namespace {

namespace tp = ::tc8::testability;

// Set SO_RCVTIMEO on `fd` from a millisecond timeout.
void setRecvTimeout(int fd, int timeout_ms) {
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

// Bind `fd` to a specific source IPv4 (ephemeral port) when src_ip_be != 0.
// Returns true on success (or when no bind was requested).
bool bindSource(int fd, std::uint32_t src_ip_be) {
    if (src_ip_be == 0U) {
        return true;
    }
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_port = 0;  // ephemeral
    src.sin_addr.s_addr = src_ip_be;
    return ::bind(fd, reinterpret_cast<const sockaddr *>(&src), sizeof(src)) == 0;
}

// One UDP request/response round trip. Returns the response bytes, or nullopt
// on socket error / timeout. Mirrors dgramUtRoundTrip in upper_tester_client
// but reads a full SOME/IP datagram rather than the opcode header.
std::optional<std::vector<std::uint8_t>> udpRoundTrip(const TestabilityConfig &cfg,
                                                      const std::vector<std::uint8_t> &req,
                                                      int timeout_ms,
                                                      std::uint32_t src_ip_be) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return std::nullopt;
    }
    if (!bindSource(fd, src_ip_be)) {
        ::close(fd);
        return std::nullopt;
    }
    setRecvTimeout(fd, timeout_ms);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(cfg.dut_port);
    dst.sin_addr.s_addr = cfg.dut_ip_be;

    if (::sendto(fd, req.data(), req.size(), 0, reinterpret_cast<const sockaddr *>(&dst),
                 sizeof(dst)) < 0) {
        ::close(fd);
        return std::nullopt;
    }

    std::uint8_t buf[1500];
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    ::close(fd);
    if (n < static_cast<ssize_t>(tp::kHeaderSize)) {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>(buf, buf + n);
}

// One TCP request/response round trip: connect, send, then read until the full
// SOME/IP message (16 + (LEN - 8) bytes) has arrived or the socket times out.
std::optional<std::vector<std::uint8_t>> tcpRoundTrip(const TestabilityConfig &cfg,
                                                      const std::vector<std::uint8_t> &req,
                                                      int timeout_ms,
                                                      std::uint32_t src_ip_be) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return std::nullopt;
    }
    if (!bindSource(fd, src_ip_be)) {
        ::close(fd);
        return std::nullopt;
    }
    setRecvTimeout(fd, timeout_ms);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(cfg.dut_port);
    dst.sin_addr.s_addr = cfg.dut_ip_be;

    if (::connect(fd, reinterpret_cast<const sockaddr *>(&dst), sizeof(dst)) < 0) {
        ::close(fd);
        return std::nullopt;
    }
    if (::send(fd, req.data(), req.size(), 0) < 0) {
        ::close(fd);
        return std::nullopt;
    }

    std::vector<std::uint8_t> resp;
    std::uint8_t buf[1500];
    // Read until the header is in, then until the declared message is complete.
    for (;;) {
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;  // timeout, peer close, or error
        }
        resp.insert(resp.end(), buf, buf + n);
        if (resp.size() < tp::kHeaderSize) {
            continue;
        }
        const auto header = tp::parseHeader(resp.data(), resp.size());
        if (!header) {
            break;
        }
        // Total message bytes = 16-byte header + (LEN - 8) payload = LEN + 8.
        const std::size_t total = static_cast<std::size_t>(header->length) + 8u;
        if (resp.size() >= total) {
            break;
        }
    }
    ::close(fd);
    if (resp.size() < tp::kHeaderSize) {
        return std::nullopt;
    }
    return resp;
}

}  // namespace

TestabilityResponse testabilityCall(const TestabilityConfig &cfg, std::uint8_t gid,
                                    std::uint8_t pid, const std::vector<std::uint8_t> &dat,
                                    int timeout_ms, std::uint32_t src_ip_be) {
    TestabilityResponse out;

    tp::Header h;
    h.service_id = cfg.service_id;
    h.method_id = tp::methodId(gid, pid);
    h.tid = tp::kTidRequest;
    h.rid = tp::kRidEOk;  // request side: return code unused, kept 0
    const std::vector<std::uint8_t> req =
        tp::buildMessage(h, dat.empty() ? nullptr : dat.data(), dat.size());

    const auto resp = cfg.use_tcp ? tcpRoundTrip(cfg, req, timeout_ms, src_ip_be)
                                  : udpRoundTrip(cfg, req, timeout_ms, src_ip_be);
    if (!resp) {
        return out;  // ok = false
    }

    const auto header = tp::parseHeader(resp->data(), resp->size());
    if (!header) {
        return out;
    }
    // Reject a stray frame: it must be a Response (TID 0x80) for THIS service
    // and primitive (GID/PID echoed in the method id, EVB clear on a response).
    if (header->service_id != cfg.service_id || header->tid != tp::kTidResponse ||
        tp::gidOf(header->method_id) != gid || tp::pidOf(header->method_id) != pid) {
        return out;
    }

    out.ok = true;
    out.tid = header->tid;
    out.rid = header->rid;
    // DAT = bytes after the 16-byte header, bounded by what actually arrived.
    if (resp->size() > tp::kHeaderSize) {
        out.dat.assign(resp->begin() + tp::kHeaderSize, resp->end());
    }
    return out;
}

std::optional<TestabilityVersion> testabilityGetVersion(const TestabilityConfig &cfg,
                                                        int timeout_ms,
                                                        std::uint32_t src_ip_be) {
    const TestabilityResponse r =
        testabilityCall(cfg, tp::kGidGeneral, tp::kPidGetVersion, {}, timeout_ms, src_ip_be);
    if (!r.eok() || r.dat.size() < 6) {
        return std::nullopt;
    }
    TestabilityVersion v;
    v.major = static_cast<std::uint16_t>((r.dat[0] << 8) | r.dat[1]);
    v.minor = static_cast<std::uint16_t>((r.dat[2] << 8) | r.dat[3]);
    v.patch = static_cast<std::uint16_t>((r.dat[4] << 8) | r.dat[5]);
    return v;
}

TestabilityResponse testabilityStartTest(const TestabilityConfig &cfg, int timeout_ms,
                                         std::uint32_t src_ip_be) {
    return testabilityCall(cfg, tp::kGidGeneral, tp::kPidStartTest, {}, timeout_ms, src_ip_be);
}

TestabilityResponse testabilityEndTest(const TestabilityConfig &cfg, std::uint16_t tc_id,
                                       const std::string &ts_name, int timeout_ms,
                                       std::uint32_t src_ip_be) {
    std::vector<std::uint8_t> dat;
    tp::appendU16(dat, tc_id);
    tp::appendText(dat, ts_name);
    return testabilityCall(cfg, tp::kGidGeneral, tp::kPidEndTest, dat, timeout_ms, src_ip_be);
}

}  // namespace tc8::stimulus
