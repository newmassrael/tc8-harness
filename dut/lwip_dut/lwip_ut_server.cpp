// Upper Tester server for the lwIP DUT fixture.
//
// Functional mirror of dut/dut_service/upper_tester_server.cpp scoped
// to the TCP opcode family (0x03..0x0B) + OpPing (0x15), rebuilt on the
// lwIP socket API. Structural differences from the Linux server, each
// forced by a stack property:
//
//   * OpQueryTcpEstablished answers from the application-visible
//     handshake completion (accept() returned / connect() completed)
//     instead of getsockopt(TCP_INFO) — lwIP's socket layer exposes no
//     PCB-state read. The pcb reaches ESTABLISHED at handshake time and
//     the acceptor polls every 200 ms, so the answer trails the wire by
//     at most one poll tick.
//   * Active opens use a non-blocking connect + select worker loop
//     instead of a blocking connect, because lwIP does not guarantee a
//     cross-thread shutdown() unblocks a connect in flight, and
//     OpCloseTcpSocket must always be able to reap the worker.
//   * OpReceiveTcpDataOob answers zero bytes unconditionally: lwIP TCP
//     implements no urgent-data path (RFC 793 §3.7 URG), so there is
//     nothing a MSG_OOB read could return. The empty answer keeps the
//     wire contract; the affected case fails visibly and is ledgered as
//     platform_known_fail.

#include "lwip_ut_server.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "lwip/sockets.h"
#include "lwip/api.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
// fd -> pcb bridge for the ABORT primitive (see destroySlot): the lwIP
// socket layer exposes no unconditional-RST path, so the server walks
// down to the raw pcb under the core lock. Private header, pinned lwIP.
// Wrapped in extern "C" because upstream declares
// lwip_socket_dbg_get_socket AFTER closing its own extern "C" block —
// without the wrapper a C++ TU sees a mangled name the C object never
// defines.
extern "C" {
#include "lwip/priv/sockets_priv.h"
}

#include "tc8/upper_tester_protocol.h"

namespace tc8::lwip_dut {
namespace {

constexpr int kAcceptPollMs = 200;
constexpr int kSendTimeoutMs = 10000;

std::uint16_t readBe16(const std::uint8_t *p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

std::uint32_t readBe32(const std::uint8_t *p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
}

struct TcpSlot {
    int listen_fd = -1;
    std::atomic<int> conn_fd{-1};
    std::atomic<bool> established{false};
    std::atomic<bool> stop{false};
    std::thread worker;
    bool active = false;
    std::uint16_t local_port = 0;
};

class UpperTesterServer {
public:
    explicit UpperTesterServer(std::uint32_t dut_ip_be)
        : dut_ip_be_(dut_ip_be) {}

    [[noreturn]] void run();

private:
    void dispatch(int fd, const sockaddr_in &peer,
                  const std::uint8_t *buf, int n);
    void respond(int fd, const sockaddr_in &peer, std::uint8_t opcode,
                 std::uint8_t req_id, std::uint8_t status,
                 const std::vector<std::uint8_t> &body);

    std::uint8_t openPassive(std::uint16_t local_port);
    std::uint8_t openActive(std::uint16_t local_port,
                            std::uint32_t remote_ip_be,
                            std::uint16_t remote_port);
    void acceptorLoop(TcpSlot *slot);
    void connectorLoop(TcpSlot *slot, std::uint32_t remote_ip_be,
                       std::uint16_t remote_port);
    // Stops the worker, closes both fds and erases the slot. `linger0`
    // arms SO_LINGER{on,0} first so the close emits RST (spec ABORT).
    bool destroySlot(std::uint8_t sid, bool linger0);
    TcpSlot *findSlot(std::uint8_t sid);
    // Case stimuli hardcode the socket ids a fresh tc8-dut process
    // hands out (1, 2, ... monotonic, NOT resetting when the registry
    // empties mid-case — multi-phase cases rely on phase 2 getting
    // sid 2). The per-case fresh sequence comes from the fixture
    // respawning this process per case (topology_stop_dut override).
    // reclaimStalePort is a backstop for deployments that cannot
    // respawn: a slot leaked by an earlier case must not hold its
    // listen port hostage.
    void reclaimStalePort(std::uint16_t local_port);
    std::uint8_t nextSidLocked();
    // socket() with an exhaustion backstop: per-worker case execution
    // is serial, so when the netconn pool still reports ENOBUFS every
    // existing slot belongs to an earlier case that skipped its
    // OpCloseTcpSocket — drop them all, loudly, and retry once.
    int createTcpSocket(const char *what);
    void destroyAllSlots(const char *why);

    static void applyTimeout(int fd, int optname, int ms);

    std::uint32_t dut_ip_be_;
    std::mutex mu_;
    std::map<std::uint8_t, std::unique_ptr<TcpSlot>> slots_;
    std::uint8_t next_sid_ = 1;
};

// Highest opcode this implementation answers. The implemented set is
// sparse (0x01/0x02 UDP and 0x0C..0x14 autoconf/DHCP/info opcodes are
// not ported yet); OpPing's single-byte capability field cannot express
// a sparse set, so the honest value is the top of the contiguous TCP
// block — a tester probing feature level sees "TCP session control
// available" and nothing more.
constexpr std::uint8_t kMaxImplementedOpcode = ut::OpReceiveTcpDataOob;

void UpperTesterServer::applyTimeout(int fd, int optname, int ms) {
    timeval tv{};
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    if (lwip_setsockopt(fd, SOL_SOCKET, optname, &tv, sizeof(tv)) < 0) {
        std::fprintf(stderr,
                     "tc8-lwip-ut: setsockopt(%s) failed on fd %d: %s\n",
                     optname == SO_RCVTIMEO ? "SO_RCVTIMEO" : "SO_SNDTIMEO",
                     fd, std::strerror(errno));
    }
}

TcpSlot *UpperTesterServer::findSlot(std::uint8_t sid) {
    auto it = slots_.find(sid);
    return it == slots_.end() ? nullptr : it->second.get();
}

void UpperTesterServer::reclaimStalePort(std::uint16_t local_port) {
    std::uint8_t stale = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto &kv : slots_) {
            if (kv.second->local_port == local_port) {
                stale = kv.first;
                break;
            }
        }
    }
    if (stale != 0) {
        std::fprintf(stderr,
                     "tc8-lwip-ut: reclaiming socket %u left on port %u by a "
                     "previous case (missing OpCloseTcpSocket)\n",
                     stale, local_port);
        destroySlot(stale, /*linger0=*/false);
    }
}

std::uint8_t UpperTesterServer::nextSidLocked() {
    // Monotonic from process start, exactly like the Linux tc8-dut.
    // Case stimuli assume the sequence keeps counting across phases of
    // one case even after every slot was closed (phase 1 -> sid 1,
    // phase 2 -> sid 2); the per-case fresh-id expectation is met by
    // the fixture respawning this process per case, never by resetting
    // the counter here.
    const std::uint8_t sid = next_sid_++;
    if (next_sid_ == 0) next_sid_ = 1;
    return sid;
}

void UpperTesterServer::destroyAllSlots(const char *why) {
    std::vector<std::uint8_t> sids;
    {
        std::lock_guard<std::mutex> lk(mu_);
        sids.reserve(slots_.size());
        for (const auto &kv : slots_) sids.push_back(kv.first);
    }
    std::fprintf(stderr,
                 "tc8-lwip-ut: dropping %zu stale socket slot(s) — %s\n",
                 sids.size(), why);
    for (const std::uint8_t sid : sids) {
        destroySlot(sid, /*linger0=*/false);
    }
}

int UpperTesterServer::createTcpSocket(const char *what) {
    int fd = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0 && errno == ENOBUFS) {
        destroyAllSlots("netconn pool exhausted by cases that skipped "
                        "OpCloseTcpSocket");
        fd = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    if (fd < 0) {
        std::fprintf(stderr, "tc8-lwip-ut: %s socket() failed: %s\n",
                     what, std::strerror(errno));
    }
    return fd;
}

std::uint8_t UpperTesterServer::openPassive(std::uint16_t local_port) {
    reclaimStalePort(local_port);
    int fd = createTcpSocket("passive");
    if (fd < 0) {
        return 0;
    }
    int on = 1;
    if (lwip_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        std::fprintf(stderr,
                     "tc8-lwip-ut: SO_REUSEADDR on passive socket failed: %s "
                     "(is SO_REUSE compiled in?)\n",
                     std::strerror(errno));
    }
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = lwip_htons(local_port);
    // Backlog 4, not 1: lwIP enforces the backlog exactly (no Linux-style
    // rounding headroom), and TCP_CONNECTION_ESTAB_01 drives multiple
    // half-open legs against one listener — a backlog-1 listener silently
    // swallows every SYN after the first embryonic connection.
    if (lwip_bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0 ||
        lwip_listen(fd, 4) < 0) {
        std::fprintf(stderr,
                     "tc8-lwip-ut: passive bind/listen on port %u failed: %s\n",
                     local_port, std::strerror(errno));
        lwip_close(fd);
        return 0;
    }

    std::lock_guard<std::mutex> lk(mu_);
    auto slot = std::make_unique<TcpSlot>();
    slot->listen_fd  = fd;
    slot->local_port = local_port;
    TcpSlot *raw = slot.get();
    const std::uint8_t sid = nextSidLocked();
    slots_.emplace(sid, std::move(slot));
    raw->worker = std::thread([this, raw] { acceptorLoop(raw); });
    std::fprintf(stderr,
                 "tc8-lwip-ut: socket %u listening on port %u (passive)\n",
                 sid, local_port);
    return sid;
}

void UpperTesterServer::acceptorLoop(TcpSlot *slot) {
    while (!slot->stop.load()) {
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(slot->listen_fd, &rs);
        timeval tv{0, kAcceptPollMs * 1000};
        const int rc = lwip_select(slot->listen_fd + 1, &rs, nullptr,
                                   nullptr, &tv);
        if (rc <= 0) continue;
        sockaddr_in peer{};
        socklen_t len = sizeof(peer);
        const int cfd = lwip_accept(slot->listen_fd,
                                    reinterpret_cast<sockaddr *>(&peer), &len);
        if (cfd < 0) {
            if (!slot->stop.load()) {
                std::fprintf(stderr, "tc8-lwip-ut: accept() failed: %s\n",
                             std::strerror(errno));
            }
            continue;
        }
        applyTimeout(cfd, SO_SNDTIMEO, kSendTimeoutMs);
        slot->conn_fd.store(cfd);
        slot->established.store(true);
        std::fprintf(stderr,
                     "tc8-lwip-ut: passive port %u accepted a connection\n",
                     slot->local_port);
        return;  // one-shot, mirrors the Linux acceptor
    }
}

std::uint8_t UpperTesterServer::openActive(std::uint16_t local_port,
                                           std::uint32_t remote_ip_be,
                                           std::uint16_t remote_port) {
    reclaimStalePort(local_port);
    int fd = createTcpSocket("active");
    if (fd < 0) {
        return 0;
    }
    int on = 1;
    if (lwip_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        std::fprintf(stderr,
                     "tc8-lwip-ut: SO_REUSEADDR on active socket failed: %s "
                     "(is SO_REUSE compiled in?)\n",
                     std::strerror(errno));
    }
    sockaddr_in local{};
    local.sin_family      = AF_INET;
    local.sin_addr.s_addr = dut_ip_be_;
    local.sin_port        = lwip_htons(local_port);
    if (lwip_bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) < 0) {
        std::fprintf(stderr,
                     "tc8-lwip-ut: active bind to port %u failed: %s\n",
                     local_port, std::strerror(errno));
        lwip_close(fd);
        return 0;
    }
    if (lwip_fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        std::fprintf(stderr, "tc8-lwip-ut: O_NONBLOCK failed: %s\n",
                     std::strerror(errno));
        lwip_close(fd);
        return 0;
    }

    std::lock_guard<std::mutex> lk(mu_);
    auto slot = std::make_unique<TcpSlot>();
    slot->conn_fd.store(fd);
    slot->active     = true;
    slot->local_port = local_port;
    TcpSlot *raw = slot.get();
    const std::uint8_t sid = nextSidLocked();
    slots_.emplace(sid, std::move(slot));
    raw->worker = std::thread([this, raw, remote_ip_be, remote_port] {
        connectorLoop(raw, remote_ip_be, remote_port);
    });
    std::fprintf(stderr,
                 "tc8-lwip-ut: socket %u connecting from port %u (active)\n",
                 sid, local_port);
    return sid;
}

void UpperTesterServer::connectorLoop(TcpSlot *slot,
                                      std::uint32_t remote_ip_be,
                                      std::uint16_t remote_port) {
    const int fd = slot->conn_fd.load();
    sockaddr_in remote{};
    remote.sin_family      = AF_INET;
    remote.sin_addr.s_addr = remote_ip_be;
    remote.sin_port        = lwip_htons(remote_port);
    const int rc = lwip_connect(fd, reinterpret_cast<sockaddr *>(&remote),
                                sizeof(remote));
    if (rc == 0) {
        slot->established.store(true);
        return;
    }
    if (errno != EINPROGRESS) {
        std::fprintf(stderr,
                     "tc8-lwip-ut: active connect to port %u failed: %s\n",
                     remote_port, std::strerror(errno));
        return;
    }
    // SYN is on the wire; poll writability until the handshake settles
    // or the slot is destroyed. The stack keeps retransmitting the SYN
    // on its own schedule — exactly what the retransmission-observation
    // cases want to watch.
    while (!slot->stop.load()) {
        fd_set ws;
        FD_ZERO(&ws);
        FD_SET(fd, &ws);
        timeval tv{0, kAcceptPollMs * 1000};
        const int sel = lwip_select(fd + 1, nullptr, &ws, nullptr, &tv);
        if (sel <= 0) continue;
        int err = 0;
        socklen_t elen = sizeof(err);
        lwip_getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err == 0) {
            applyTimeout(fd, SO_SNDTIMEO, kSendTimeoutMs);
            slot->established.store(true);
            std::fprintf(stderr,
                         "tc8-lwip-ut: active connect to port %u established\n",
                         remote_port);
        } else {
            std::fprintf(stderr,
                         "tc8-lwip-ut: active connect to port %u failed: %s\n",
                         remote_port, std::strerror(err));
        }
        return;
    }
}

bool UpperTesterServer::destroySlot(std::uint8_t sid, bool linger0) {
    std::unique_ptr<TcpSlot> owned;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = slots_.find(sid);
        if (it == slots_.end()) return false;
        owned = std::move(it->second);
        slots_.erase(it);
    }
    owned->stop.store(true);
    if (owned->worker.joinable()) owned->worker.join();
    const int cfd = owned->conn_fd.load();
    if (cfd >= 0) {
        if (linger0) {
            // Spec ABORT primitive: RST out, connection gone. The Linux
            // recipe (SO_LINGER{on,0} + close) does not map — lwIP only
            // aborts a lingering close when unsent/unacked data remains
            // (api_msg.c lwip_netconn_do_close_internal), an empty queue
            // always closes gracefully with FIN. tcp_abort() on the raw
            // pcb is the stack's actual abort primitive; the err
            // callback detaches the netconn so the lwip_close below
            // only reaps the socket slot.
            LOCK_TCPIP_CORE();
            struct lwip_sock *s = lwip_socket_dbg_get_socket(cfd);
            if (s != nullptr && s->conn != nullptr &&
                NETCONNTYPE_GROUP(s->conn->type) == NETCONN_TCP &&
                s->conn->pcb.tcp != nullptr) {
                tcp_abort(s->conn->pcb.tcp);
            } else {
                std::fprintf(stderr,
                             "tc8-lwip-ut: abort on socket %u found no live "
                             "TCP pcb — connection already gone, close only\n",
                             sid);
            }
            UNLOCK_TCPIP_CORE();
        }
        lwip_close(cfd);
    }
    if (owned->listen_fd >= 0) lwip_close(owned->listen_fd);
    std::fprintf(stderr, "tc8-lwip-ut: socket %u %s\n", sid,
                 linger0 ? "aborted (RST)" : "closed");
    return true;
}

void UpperTesterServer::respond(int fd, const sockaddr_in &peer,
                                std::uint8_t opcode, std::uint8_t req_id,
                                std::uint8_t status,
                                const std::vector<std::uint8_t> &body) {
    std::vector<std::uint8_t> frame;
    frame.reserve(3 + body.size());
    frame.push_back(static_cast<std::uint8_t>(opcode | ut::kResponseBit));
    frame.push_back(req_id);
    frame.push_back(status);
    frame.insert(frame.end(), body.begin(), body.end());
    if (lwip_sendto(fd, frame.data(), frame.size(), 0,
                    reinterpret_cast<const sockaddr *>(&peer),
                    sizeof(peer)) < 0) {
        std::fprintf(stderr, "tc8-lwip-ut: response send failed: %s\n",
                     std::strerror(errno));
    }
}

void UpperTesterServer::dispatch(int fd, const sockaddr_in &peer,
                                 const std::uint8_t *buf, int n) {
    const std::uint8_t opcode = buf[0];
    const std::uint8_t req_id = buf[1];
    std::vector<std::uint8_t> body;

    switch (opcode) {
    case ut::OpPing:
        body.push_back(kMaxImplementedOpcode);
        respond(fd, peer, opcode, req_id, ut::kStatusOk, body);
        return;

    case ut::OpOpenTcpSocket: {
        if (n < 2 + 1 + 2) {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        const std::uint8_t type        = buf[2];
        const std::uint16_t local_port = readBe16(buf + 3);
        std::uint8_t sid = 0;
        std::uint8_t status = ut::kStatusOk;
        if (type == ut::kSocketTypePassive) {
            sid = openPassive(local_port);
            if (sid == 0) status = ut::kStatusBindFailed;
        } else if (type == ut::kSocketTypeActive) {
            if (n < 2 + 1 + 2 + 4 + 2) {
                respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
                return;
            }
            const std::uint32_t remote_ip_be = lwip_htonl(readBe32(buf + 5));
            const std::uint16_t remote_port  = readBe16(buf + 9);
            sid = openActive(local_port, remote_ip_be, remote_port);
            if (sid == 0) status = ut::kStatusConnectFailed;
        } else {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        if (sid != 0) body.push_back(sid);
        respond(fd, peer, opcode, req_id, status, body);
        return;
    }

    case ut::OpCloseTcpSocket:
    case ut::OpAbortTcpSocket: {
        if (n < 2 + 1) {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        const bool found =
            destroySlot(buf[2], opcode == ut::OpAbortTcpSocket);
        respond(fd, peer, opcode, req_id,
                found ? ut::kStatusOk : ut::kStatusUnknownSocket, body);
        return;
    }

    case ut::OpQueryTcpEstablished: {
        if (n < 2 + 1) {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        std::lock_guard<std::mutex> lk(mu_);
        TcpSlot *slot = findSlot(buf[2]);
        if (slot == nullptr) {
            respond(fd, peer, opcode, req_id, ut::kStatusUnknownSocket, body);
            return;
        }
        body.push_back(slot->established.load() ? 1 : 0);
        respond(fd, peer, opcode, req_id, ut::kStatusOk, body);
        return;
    }

    case ut::OpSendTcpData:
    case ut::OpSendTcpDataPattern: {
        const bool pattern = (opcode == ut::OpSendTcpDataPattern);
        const int header = pattern ? (2 + 1 + 1 + 2) : (2 + 1 + 2);
        if (n < header) {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        std::vector<std::uint8_t> payload;
        if (pattern) {
            payload.assign(readBe16(buf + 4), buf[3]);
        } else {
            const std::uint16_t len = readBe16(buf + 3);
            if (n < header + len) {
                respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
                return;
            }
            payload.assign(buf + 5, buf + 5 + len);
        }
        int cfd = -1;
        {
            std::lock_guard<std::mutex> lk(mu_);
            TcpSlot *slot = findSlot(buf[2]);
            if (slot != nullptr) cfd = slot->conn_fd.load();
            if (slot == nullptr) {
                respond(fd, peer, opcode, req_id, ut::kStatusUnknownSocket,
                        body);
                return;
            }
        }
        std::size_t off = 0;
        while (off < payload.size()) {
            const ssize_t rc = lwip_send(cfd, payload.data() + off,
                                         payload.size() - off, 0);
            if (rc <= 0) {
                std::fprintf(stderr,
                             "tc8-lwip-ut: send on socket %u failed after "
                             "%zu/%zu bytes: %s\n",
                             buf[2], off, payload.size(),
                             std::strerror(errno));
                respond(fd, peer, opcode, req_id, ut::kStatusSendFailed, body);
                return;
            }
            off += static_cast<std::size_t>(rc);
        }
        respond(fd, peer, opcode, req_id, ut::kStatusOk, body);
        return;
    }

    case ut::OpReceiveTcpData: {
        if (n < 2 + 1 + 2 + 2) {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        const std::uint16_t expected =
            std::min<std::uint16_t>(readBe16(buf + 3), ut::kMaxPayload);
        const std::uint16_t timeout_ms = readBe16(buf + 5);
        int cfd = -1;
        {
            std::lock_guard<std::mutex> lk(mu_);
            TcpSlot *slot = findSlot(buf[2]);
            if (slot == nullptr) {
                respond(fd, peer, opcode, req_id, ut::kStatusUnknownSocket,
                        body);
                return;
            }
            cfd = slot->conn_fd.load();
        }
        std::vector<std::uint8_t> data;
        if (cfd >= 0) {
            applyTimeout(cfd, SO_RCVTIMEO, timeout_ms > 0 ? timeout_ms : 1);
            data.resize(expected);
            std::size_t got = 0;
            while (got < expected) {
                const ssize_t rc =
                    lwip_recv(cfd, data.data() + got, expected - got, 0);
                if (rc <= 0) break;  // timeout, peer close, or error
                got += static_cast<std::size_t>(rc);
            }
            data.resize(got);
        }
        body.push_back(static_cast<std::uint8_t>(data.size() >> 8));
        body.push_back(static_cast<std::uint8_t>(data.size() & 0xFF));
        body.insert(body.end(), data.begin(), data.end());
        respond(fd, peer, opcode, req_id, ut::kStatusOk, body);
        return;
    }

    case ut::OpReceiveTcpDataOob: {
        if (n < 2 + 1 + 2 + 2) {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        std::lock_guard<std::mutex> lk(mu_);
        if (findSlot(buf[2]) == nullptr) {
            respond(fd, peer, opcode, req_id, ut::kStatusUnknownSocket, body);
            return;
        }
        std::fprintf(stderr,
                     "tc8-lwip-ut: OpReceiveTcpDataOob on socket %u — lwIP "
                     "TCP has no urgent-data path (RFC 793 URG unsupported); "
                     "answering zero urgent bytes\n",
                     buf[2]);
        body.push_back(0);
        body.push_back(0);
        respond(fd, peer, opcode, req_id, ut::kStatusOk, body);
        return;
    }

    case ut::OpShutdownTcpSocketWr: {
        if (n < 2 + 1) {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        std::lock_guard<std::mutex> lk(mu_);
        TcpSlot *slot = findSlot(buf[2]);
        if (slot == nullptr || slot->conn_fd.load() < 0) {
            respond(fd, peer, opcode, req_id, ut::kStatusUnknownSocket, body);
            return;
        }
        if (lwip_shutdown(slot->conn_fd.load(), SHUT_WR) < 0) {
            std::fprintf(stderr,
                         "tc8-lwip-ut: shutdown(WR) on socket %u failed: %s\n",
                         buf[2], std::strerror(errno));
            respond(fd, peer, opcode, req_id, ut::kStatusSendFailed, body);
            return;
        }
        respond(fd, peer, opcode, req_id, ut::kStatusOk, body);
        return;
    }

    default:
        std::fprintf(stderr,
                     "tc8-lwip-ut: opcode 0x%02X not implemented on the lwIP "
                     "fixture (req_id %u)\n",
                     opcode, req_id);
        respond(fd, peer, opcode, req_id, ut::kStatusUnknownOpcode, body);
        return;
    }
}

[[noreturn]] void UpperTesterServer::run() {
    const int fd = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        std::fprintf(stderr, "tc8-lwip-ut: UDP socket() failed: %s\n",
                     std::strerror(errno));
        abort();
    }
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = lwip_htons(ut::kPort);
    if (lwip_bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        std::fprintf(stderr,
                     "tc8-lwip-ut: bind to UDP port %u failed: %s\n",
                     ut::kPort, std::strerror(errno));
        abort();
    }
    std::fprintf(stderr,
                 "tc8-lwip-ut: serving on UDP port %u (opcodes 0x03..0x0B + "
                 "OpPing; max_opcode reported 0x%02X)\n",
                 ut::kPort, kMaxImplementedOpcode);

    std::uint8_t buf[ut::kMaxPayload + 16];
    for (;;) {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        const int n = lwip_recvfrom(fd, buf, sizeof(buf), 0,
                                    reinterpret_cast<sockaddr *>(&peer),
                                    &plen);
        if (n < 2) {
            if (n < 0) {
                std::fprintf(stderr, "tc8-lwip-ut: recvfrom failed: %s\n",
                             std::strerror(errno));
            } else {
                std::fprintf(stderr,
                             "tc8-lwip-ut: dropping %d-byte runt frame\n", n);
            }
            continue;
        }
        dispatch(fd, peer, buf, n);
    }
}

}  // namespace

void StartUpperTesterServer(std::uint32_t dut_ip_be) {
    // Leaked deliberately: the server lives for the process lifetime
    // and the fixture is torn down with SIGKILL by the topology conf.
    auto *server = new UpperTesterServer(dut_ip_be);
    std::thread([server] { server->run(); }).detach();
}

}  // namespace tc8::lwip_dut
