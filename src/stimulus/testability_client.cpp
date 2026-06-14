#include "stimulus/testability_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <chrono>
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

// Open a UDP client socket, bound to src_ip_be when nonzero. -1 on failure
// (caller closes). The single place the control-plane UDP socket is created, so
// the one-shot round trip and the listen/event flow set it up identically.
int openUdpClient(std::uint32_t src_ip_be) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (!bindSource(fd, src_ip_be)) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// The DUT testability endpoint address from cfg.
sockaddr_in dutAddr(const TestabilityConfig &cfg) {
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(cfg.dut_port);
    dst.sin_addr.s_addr = cfg.dut_ip_be;
    return dst;
}

// One UDP request/response round trip. Returns the response bytes, or nullopt
// on socket error / timeout. Mirrors dgramUtRoundTrip in upper_tester_client
// but reads a full SOME/IP datagram rather than the opcode header.
std::optional<std::vector<std::uint8_t>> udpRoundTrip(const TestabilityConfig &cfg,
                                                      const std::vector<std::uint8_t> &req,
                                                      int timeout_ms,
                                                      std::uint32_t src_ip_be) {
    const int fd = openUdpClient(src_ip_be);
    if (fd < 0) {
        return std::nullopt;
    }
    setRecvTimeout(fd, timeout_ms);

    const sockaddr_in dst = dutAddr(cfg);
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

// Outcome of an arm-then-collect-event round trip (LISTEN_AND_ACCEPT,
// RECEIVE_AND_FORWARD). DAT vectors are the bytes after the 16-byte header.
struct ArmedEventResult {
    bool armed = false;                    // request round-tripped with an E_OK Response
    std::vector<std::uint8_t> resp_dat;    // Response DAT (valid when armed)
    bool event_received = false;           // a well-formed Event of this SP arrived
    std::vector<std::uint8_t> event_dat;   // Event DAT (valid when event_received)
};

// An armed async-event SP socket: the UDP fd left open after the arm request's
// E_OK Response and `on_armed`, ready for the caller to collect one or more
// Events. fd == -1 (armed == false) when the arm failed; otherwise the caller
// owns the open fd and must ::close it.
struct ArmedSocket {
    bool armed = false;
    std::vector<std::uint8_t> resp_dat;
    int fd = -1;
};

// Receive one Event (TID 0x02 / EVB set) of SP (gid,pid) on an already-armed
// socket whose recv timeout the caller has set; returns the Event DAT (bytes
// after the 16-byte header) or nullopt on timeout / malformed / wrong-SP frame.
// The Event-parse SSOT shared by the single-Event (accept) and accumulating
// (receive-and-forward) collectors.
std::optional<std::vector<std::uint8_t>> recvSpEvent(int fd, std::uint8_t gid, std::uint8_t pid) {
    std::uint8_t buf[2048];
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n < static_cast<ssize_t>(tp::kHeaderSize)) {
        return std::nullopt;
    }
    const auto evh = tp::parseHeader(buf, static_cast<std::size_t>(n));
    if (!evh || evh->tid != tp::kTidEvent || !tp::isEvent(evh->method_id) ||
        tp::gidOf(evh->method_id) != gid || tp::pidOf(evh->method_id) != pid) {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>(buf + tp::kHeaderSize, buf + n);
}

// Arm an async-event SP over one persistent UDP socket — the SSOT for the
// LISTEN_AND_ACCEPT / RECEIVE_AND_FORWARD arm shape. The socket carries the
// request, its E_OK Response, and the later Event(s) (the DUT routes them to the
// request's source address). `on_armed` runs after the Response and before any
// Event wait, so the caller drives whatever produces the Event(s). Returns the
// open fd (armed == true) for the caller to collect Events on and ::close, or
// fd == -1 (armed == false) when the open / send / Response step failed.
ArmedSocket armEventSocket(const TestabilityConfig &cfg, std::uint8_t gid, std::uint8_t pid,
                           const std::vector<std::uint8_t> &req_dat,
                           const std::function<void()> &on_armed, int resp_timeout_ms,
                           std::uint32_t src_ip_be) {
    ArmedSocket res;

    const int fd = openUdpClient(src_ip_be);
    if (fd < 0) {
        return res;
    }
    setRecvTimeout(fd, resp_timeout_ms);
    const sockaddr_in dst = dutAddr(cfg);

    tp::Header h;
    h.service_id = cfg.service_id;
    h.method_id = tp::methodId(gid, pid);
    h.tid = tp::kTidRequest;
    const std::vector<std::uint8_t> req = tp::buildMessage(h, req_dat.data(), req_dat.size());
    if (::sendto(fd, req.data(), req.size(), 0, reinterpret_cast<const sockaddr *>(&dst),
                 sizeof(dst)) < 0) {
        ::close(fd);
        return res;
    }

    // Response (TID 0x80) — must be an E_OK Response to this SP before we wait.
    std::uint8_t buf[2048];
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    const auto resp = (n >= static_cast<ssize_t>(tp::kHeaderSize))
                          ? tp::parseHeader(buf, static_cast<std::size_t>(n))
                          : std::nullopt;
    if (!resp || resp->tid != tp::kTidResponse || resp->rid != tp::kRidEOk ||
        tp::gidOf(resp->method_id) != gid || tp::pidOf(resp->method_id) != pid) {
        ::close(fd);
        return res;
    }
    res.armed = true;
    res.resp_dat.assign(buf + tp::kHeaderSize, buf + n);
    res.fd = fd;

    if (on_armed) {
        on_armed();
    }
    return res;
}

// Arm an async-event SP and collect its first Event — the single-Event shape
// LISTEN_AND_ACCEPT uses. Wraps armEventSocket + one recvSpEvent.
ArmedEventResult armAndCollectEvent(const TestabilityConfig &cfg, std::uint8_t gid,
                                    std::uint8_t pid, const std::vector<std::uint8_t> &req_dat,
                                    const std::function<void()> &on_armed, int resp_timeout_ms,
                                    int event_timeout_ms, std::uint32_t src_ip_be) {
    ArmedEventResult res;
    ArmedSocket arm = armEventSocket(cfg, gid, pid, req_dat, on_armed, resp_timeout_ms, src_ip_be);
    res.armed = arm.armed;
    res.resp_dat = std::move(arm.resp_dat);
    if (!arm.armed) {
        return res;
    }
    setRecvTimeout(arm.fd, event_timeout_ms);
    const auto ev = recvSpEvent(arm.fd, gid, pid);
    ::close(arm.fd);
    if (ev) {
        res.event_received = true;
        res.event_dat = *ev;
    }
    return res;
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

std::optional<std::uint16_t> testabilityCreateAndBind(const TestabilityConfig &cfg,
                                                      std::uint8_t gid, bool do_bind,
                                                      std::uint16_t local_port,
                                                      std::uint32_t local_addr_be,
                                                      int timeout_ms, std::uint32_t src_ip_be) {
    std::vector<std::uint8_t> dat;
    dat.push_back(do_bind ? 0x01 : 0x00);    // doBind
    tp::appendU16(dat, local_port);          // localPort (0xFFFF = PORT_ANY)
    tp::appendIpv4Addr(dat, local_addr_be);  // localAddr (ipxaddr)
    const TestabilityResponse r =
        testabilityCall(cfg, gid, tp::kPidCreateAndBind, dat, timeout_ms, src_ip_be);
    if (!r.eok() || r.dat.size() < 2) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>((r.dat[0] << 8) | r.dat[1]);
}

TestabilityResponse testabilityUdpSendData(const TestabilityConfig &cfg, std::uint16_t socket_id,
                                           std::uint16_t total_len, std::uint16_t dest_port,
                                           std::uint32_t dest_addr_be,
                                           const std::vector<std::uint8_t> &data, int timeout_ms,
                                           std::uint32_t src_ip_be) {
    std::vector<std::uint8_t> dat;
    tp::appendU16(dat, socket_id);
    tp::appendU16(dat, total_len);
    tp::appendU16(dat, dest_port);
    tp::appendIpv4Addr(dat, dest_addr_be);
    tp::appendVint8(dat, data.empty() ? nullptr : data.data(), data.size());
    return testabilityCall(cfg, tp::kGidUdp, tp::kPidSendData, dat, timeout_ms, src_ip_be);
}

TestabilityResponse testabilityTcpConnect(const TestabilityConfig &cfg, std::uint16_t socket_id,
                                          std::uint16_t dest_port, std::uint32_t dest_addr_be,
                                          int timeout_ms, std::uint32_t src_ip_be) {
    std::vector<std::uint8_t> dat;
    tp::appendU16(dat, socket_id);
    tp::appendU16(dat, dest_port);
    tp::appendIpv4Addr(dat, dest_addr_be);
    return testabilityCall(cfg, tp::kGidTcp, tp::kPidConnect, dat, timeout_ms, src_ip_be);
}

TestabilityResponse testabilityTcpSendData(const TestabilityConfig &cfg, std::uint16_t socket_id,
                                           std::uint16_t total_len, std::uint8_t flags,
                                           const std::vector<std::uint8_t> &data, int timeout_ms,
                                           std::uint32_t src_ip_be) {
    std::vector<std::uint8_t> dat;
    tp::appendU16(dat, socket_id);
    tp::appendU16(dat, total_len);
    dat.push_back(flags);
    tp::appendVint8(dat, data.empty() ? nullptr : data.data(), data.size());
    return testabilityCall(cfg, tp::kGidTcp, tp::kPidSendData, dat, timeout_ms, src_ip_be);
}

// CLOSE_SOCKET request-encoding SSOT (PRS_TPSP §6.10): socketId(u16) + optional
// abort(u8). The graceful and abortive public wrappers differ only in the abort
// byte, so the wire shape lives here once.
static TestabilityResponse closeSocketCall(const TestabilityConfig &cfg, std::uint8_t gid,
                                           std::uint16_t socket_id, bool abort, int timeout_ms,
                                           std::uint32_t src_ip_be) {
    std::vector<std::uint8_t> dat;
    tp::appendU16(dat, socket_id);
    if (abort) {
        dat.push_back(1U);  // abort = true (TCP only)
    }
    return testabilityCall(cfg, gid, tp::kPidCloseSocket, dat, timeout_ms, src_ip_be);
}

TestabilityResponse testabilityCloseSocket(const TestabilityConfig &cfg, std::uint8_t gid,
                                           std::uint16_t socket_id, int timeout_ms,
                                           std::uint32_t src_ip_be) {
    return closeSocketCall(cfg, gid, socket_id, /*abort=*/false, timeout_ms, src_ip_be);
}

TestabilityResponse testabilityAbortSocket(const TestabilityConfig &cfg, std::uint8_t gid,
                                           std::uint16_t socket_id, int timeout_ms,
                                           std::uint32_t src_ip_be) {
    return closeSocketCall(cfg, gid, socket_id, /*abort=*/true, timeout_ms, src_ip_be);
}

TestabilityResponse testabilityShutdown(const TestabilityConfig &cfg, std::uint8_t gid,
                                        std::uint16_t socket_id, std::uint8_t type_id,
                                        int timeout_ms, std::uint32_t src_ip_be) {
    std::vector<std::uint8_t> dat;
    tp::appendU16(dat, socket_id);  // socketId(uint16)
    dat.push_back(type_id);         // typeId(uint8)
    return testabilityCall(cfg, gid, tp::kPidShutdown, dat, timeout_ms, src_ip_be);
}

TestabilityResponse testabilityTcpListen(const TestabilityConfig &cfg,
                                         std::uint16_t listen_socket_id, std::uint16_t max_con,
                                         int timeout_ms, std::uint32_t src_ip_be) {
    // LISTEN_AND_ACCEPT request DAT (PRS_TPSP §6.10): listenSocketId(u16) +
    // maxCon(u16) — the same framing testabilityTcpListenAndAccept builds below.
    // Listen-only routes through the generic round-trip engine (a throwaway fd)
    // because it never awaits the async Event; only the accept variant needs the
    // persistent fd that keeps the Event's return path open.
    std::vector<std::uint8_t> dat;
    tp::appendU16(dat, listen_socket_id);
    tp::appendU16(dat, max_con);
    return testabilityCall(cfg, tp::kGidTcp, tp::kPidListenAndAccept, dat, timeout_ms, src_ip_be);
}

TestabilityAcceptEvent testabilityTcpListenAndAccept(const TestabilityConfig &cfg,
                                                     std::uint16_t listen_socket_id,
                                                     std::uint16_t max_con,
                                                     const std::function<void()> &on_listening,
                                                     int resp_timeout_ms, int event_timeout_ms,
                                                     std::uint32_t src_ip_be) {
    TestabilityAcceptEvent ev;

    // LISTEN_AND_ACCEPT request: listenSocketId(u16) + maxCon(u16).
    std::vector<std::uint8_t> dat;
    tp::appendU16(dat, listen_socket_id);
    tp::appendU16(dat, max_con);
    const auto r = armAndCollectEvent(cfg, tp::kGidTcp, tp::kPidListenAndAccept, dat, on_listening,
                                      resp_timeout_ms, event_timeout_ms, src_ip_be);
    if (!r.event_received) {
        return ev;  // listen failed or no accept Event within the timeout
    }
    // Event DAT: listenSocketId(u16) + newSocketId(u16) + port(u16) + addr(ipxaddr).
    const std::uint8_t *edat = r.event_dat.data();
    const std::size_t edat_len = r.event_dat.size();
    if (edat_len < 2 + 2 + 2) {
        return ev;
    }
    ev.listen_socket_id = tp::readU16(edat);
    ev.new_socket_id = tp::readU16(edat + 2);
    ev.client_port = tp::readU16(edat + 4);
    std::size_t off = 6;
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (tp::readVint8(edat, edat_len, off, addr_body, addr_len) && addr_len == 4) {
        std::memcpy(&ev.client_addr_be, addr_body, 4);
    }
    ev.received = true;
    return ev;
}

TestabilityForwardResult testabilityReceiveAndForward(
    const TestabilityConfig &cfg, std::uint16_t socket_id, std::uint16_t max_fwd,
    std::uint16_t max_len, const std::function<void()> &on_armed, int resp_timeout_ms,
    int event_timeout_ms, std::uint32_t src_ip_be) {
    TestabilityForwardResult res;

    // RECEIVE_AND_FORWARD request: socketId(u16) + maxFwd(u16) + maxLen(u16).
    std::vector<std::uint8_t> dat;
    tp::appendU16(dat, socket_id);
    tp::appendU16(dat, max_fwd);
    tp::appendU16(dat, max_len);
    ArmedSocket arm = armEventSocket(cfg, tp::kGidTcp, tp::kPidReceiveAndForward, dat, on_armed,
                                     resp_timeout_ms, src_ip_be);
    res.ok = arm.armed;
    if (arm.resp_dat.size() >= 2) {
        res.drop_cnt = tp::readU16(arm.resp_dat.data());  // Response DAT: dropCnt(u16)
    }
    if (!arm.armed) {
        return res;
    }

    // Accumulate forward Events until max_len bytes are gathered or the event
    // budget expires — mirroring the opcode OpReceiveTcpData recv-loop so a
    // stream the DUT reads as several recv()s (one forward Event each,
    // PRS_TPSP §6.10) reassembles into one buffer on both backends. A limitless
    // arm (max_len 0xFFFF) has no byte target, so it collects a single Event as
    // before — no seam caller uses the limitless mode.
    const bool limitless = (max_len == 0xFFFF);
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(event_timeout_ms);
    bool first = true;
    while (limitless ? first : res.payload.size() < max_len) {
        first = false;
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            break;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        setRecvTimeout(arm.fd, static_cast<int>(remaining > 0 ? remaining : 1));
        const auto ev = recvSpEvent(arm.fd, tp::kGidTcp, tp::kPidReceiveAndForward);
        if (!ev || ev->size() < 2) {
            break;  // timeout / malformed — stop with what we have
        }
        // Event DAT: fullLen(u16) + payload(vint8). fullLen is THIS recv()'s
        // length; sum them for the bulk total, append each forwarded chunk.
        res.full_len = static_cast<std::uint16_t>(res.full_len + tp::readU16(ev->data()));
        std::size_t off = 2;
        const std::uint8_t *body = nullptr;
        std::uint16_t body_len = 0;
        if (tp::readVint8(ev->data(), ev->size(), off, body, body_len)) {
            res.payload.insert(res.payload.end(), body, body + body_len);
        }
    }
    ::close(arm.fd);
    return res;
}

}  // namespace tc8::stimulus
