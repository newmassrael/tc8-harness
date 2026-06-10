// Upper Tester server for the lwIP DUT fixture.
//
// Functional mirror of dut/dut_service/upper_tester_server.cpp scoped
// to the UDP opcode family (0x01/0x02/0x14) + the TCP opcode family
// (0x03..0x0B) + OpPing (0x15), rebuilt on the lwIP socket API.
// Structural differences from the Linux server, each forced by a stack
// property:
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
//   * The UDP data listener (the receipt log OpGetReceivedUdp consults)
//     is a core-API udp pcb with a recv callback, not a socket thread:
//     the callback observes the original IP destination via
//     ip_current_dest_addr() — the information IP_PKTINFO provides on
//     Linux — without compiling in LWIP_NETBUF_RECVINFO, and receipts
//     cost no extra application thread.
//   * OpTriggerSendUdp's src-IP override (§4.6.5.5 UDP_USER_INTERFACE_07
//     <DIface-0-IP> alias) maps to udp_sendto_if_src(): lwIP has no
//     IPv4 netif-alias concept to bind to, and the core API emits from
//     a caller-specified source address directly, which is exactly the
//     spec's "caller-specified Source IP" axis.

#include "lwip_ut_server.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include "lwip/sockets.h"
#include "lwip/api.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "lwip/udp.h"
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

void appendBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

// IP addresses travel MSB-first on the UT wire (172,16,0,1 for
// 172.16.0.1) — a network-byte-order u32's memory layout verbatim,
// on any host endianness.
void appendNboIp(std::vector<std::uint8_t> &b, std::uint32_t ip_be) {
    const auto *p = reinterpret_cast<const std::uint8_t *>(&ip_be);
    b.insert(b.end(), p, p + 4);
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

// Last UDP receipt per (dst_port, dst_ip) — same binning as the Linux
// data listener's log. `payload` holds the first ut::kMaxPayload bytes
// so the Confirmation datagram stays under MTU; `original_len` reports
// what the application layer actually saw (§4.6.5.4 UDP_FIELDS_12
// verdicts on the 65 507-byte original, not the truncated copy).
struct UdpReceipt {
    std::uint32_t src_ip_be    = 0;
    std::uint16_t src_port     = 0;
    std::size_t   original_len = 0;
    std::vector<std::uint8_t> payload;
};

class UpperTesterServer {
public:
    explicit UpperTesterServer(std::uint32_t dut_ip_be)
        : dut_ip_be_(dut_ip_be) {}

    [[noreturn]] void run();

    // SIGTERM teardown — see AbortUpperTesterSlots() in the header.
    void abortAllSlots() {
        destroyAllSlots("SIGTERM teardown — RST so tester-side halves "
                        "reach CLOSED instead of orphaning in FIN-WAIT-2",
                        /*linger0=*/true);
    }

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
    void destroyAllSlots(const char *why, bool linger0);

    // UDP opcode family (0x01/0x02/0x14) backend, all on the core
    // (raw) udp API under the tcpip core lock.
    void startUdpDataListener();
    static void udpDataRecv(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                            const ip_addr_t *addr, u16_t port);
    bool triggerSendUdp(std::uint16_t src_port, std::uint32_t dst_ip_be,
                        std::uint16_t dst_port, const std::uint8_t *payload,
                        std::uint16_t payload_len,
                        std::uint32_t src_ip_override_be);
    std::uint8_t createUdpReceivePorts(std::uint8_t count);

    static void applyTimeout(int fd, int optname, int ms);

    std::uint32_t dut_ip_be_;
    std::mutex mu_;
    std::map<std::uint8_t, std::unique_ptr<TcpSlot>> slots_;
    std::uint8_t next_sid_ = 1;

    // Receipt log: written by udpDataRecv in the tcpip thread, read by
    // the UT dispatch thread. udp_mu_ is never held across a core-lock
    // acquisition (the tcpip thread holds the core lock while calling
    // the recv callback — nesting the other way would deadlock).
    std::mutex udp_mu_;
    std::map<std::pair<std::uint16_t, std::uint32_t>, UdpReceipt>
        udp_receipts_;
    // OpCreateUdpReceivePorts pcbs, held for the process lifetime like
    // the Linux server's fd list (the fixture respawns this process per
    // case, so "lifetime" is one case). Touched only by the single UT
    // dispatch thread — no lock needed.
    std::vector<struct udp_pcb *> udp_receive_ports_;
};

// Highest opcode this implementation answers. The implemented set is
// sparse (0x0C..0x13 autoconf/DHCP/info opcodes are not ported;
// OpCreateUdpReceivePorts 0x14 IS, beyond the gap); OpPing's
// single-byte capability field cannot express a sparse set, so the
// honest value is the top of the contiguous 0x01..0x0B block — a
// tester probing feature level sees "UDP + TCP session control
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

void UpperTesterServer::destroyAllSlots(const char *why, bool linger0) {
    std::vector<std::uint8_t> sids;
    {
        std::lock_guard<std::mutex> lk(mu_);
        sids.reserve(slots_.size());
        for (const auto &kv : slots_) sids.push_back(kv.first);
    }
    if (sids.empty()) {
        return;
    }
    std::fprintf(stderr,
                 "tc8-lwip-ut: dropping %zu stale socket slot(s) — %s\n",
                 sids.size(), why);
    for (const std::uint8_t sid : sids) {
        destroySlot(sid, linger0);
    }
}

int UpperTesterServer::createTcpSocket(const char *what) {
    int fd = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0 && errno == ENOBUFS) {
        // linger0: a stale slot's tester half is already half-closed or
        // abandoned; RST frees its quad immediately instead of minting
        // a FIN-WAIT-2 orphan.
        destroyAllSlots("netconn pool exhausted by cases that skipped "
                        "OpCloseTcpSocket",
                        /*linger0=*/true);
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

void UpperTesterServer::startUdpDataListener() {
    LOCK_TCPIP_CORE();
    struct udp_pcb *pcb = udp_new();
    err_t err = ERR_MEM;
    if (pcb != nullptr) {
        err = udp_bind(pcb, IP_ANY_TYPE, ut::kDataPort);
        if (err == ERR_OK) {
            udp_recv(pcb, &UpperTesterServer::udpDataRecv, this);
        } else {
            udp_remove(pcb);
        }
    }
    UNLOCK_TCPIP_CORE();
    if (err != ERR_OK) {
        std::fprintf(stderr,
                     "tc8-lwip-ut: data listener bind to UDP port %u failed "
                     "(err %d) — OpGetReceivedUdp will answer received=0\n",
                     ut::kDataPort, static_cast<int>(err));
        return;
    }
    std::fprintf(stderr,
                 "tc8-lwip-ut: data listener on UDP port %u (core-API pcb)\n",
                 ut::kDataPort);
}

void UpperTesterServer::udpDataRecv(void *arg, struct udp_pcb *pcb,
                                    struct pbuf *p, const ip_addr_t *addr,
                                    u16_t port) {
    auto *self = static_cast<UpperTesterServer *>(arg);
    if (p == nullptr) {
        return;
    }
    const std::uint32_t src_ip_be = ip_addr_get_ip4_u32(addr);
    const std::uint32_t dst_ip_be =
        ip_addr_get_ip4_u32(ip_current_dest_addr());

    // §4.4.4.5 IPv4_ADDRESSING_02 conformance, the same application-
    // layer rule as the Linux tc8-dut data listener: datagrams addressed
    // to the iface directed-broadcast are silently discarded (RFC 1122
    // §3.2.1.3 SHOULD) and never enter the receipt log. Bitwise NBO
    // arithmetic — AND/OR/NOT are bytewise, no byte-order conversion
    // needed.
    const struct netif *nif = netif_default;
    if (nif != nullptr) {
        const std::uint32_t if_ip = ip4_addr_get_u32(netif_ip4_addr(nif));
        const std::uint32_t mask  = ip4_addr_get_u32(netif_ip4_netmask(nif));
        if (dst_ip_be == ((if_ip & mask) | ~mask)) {
            pbuf_free(p);
            return;
        }
    }
    // §4.6.5.6 UDP_INTRODUCTION_02 conformance: RFC 1122 §4.1.1 has
    // multicast datagrams discarded unless the application requested
    // the group (and TC8 inverts the SHOULD-allow to a deny outright);
    // no UT consumer ever joins a group. The drop must live here
    // because lwIP's ip4_input accepts EVERY multicast destination
    // unconditionally when LWIP_IGMP=0 (src/core/ipv4/ip4.c, the
    // `#else LWIP_IGMP` branch) — and compiling IGMP in would not
    // help, since igmp_start auto-joins 224.0.0.1 on netif-up. The
    // Linux tc8-dut gets the same observable from its kernel's
    // not-joined filter.
    if (ip4_addr_ismulticast(ip_2_ip4(ip_current_dest_addr()))) {
        pbuf_free(p);
        return;
    }

    UdpReceipt rec;
    rec.src_ip_be    = src_ip_be;
    rec.src_port     = port;
    rec.original_len = p->tot_len;
    const std::uint16_t copy_len = static_cast<std::uint16_t>(
        std::min<std::uint32_t>(p->tot_len, ut::kMaxPayload));
    rec.payload.resize(copy_len);
    pbuf_copy_partial(p, rec.payload.data(), copy_len, 0);
    {
        std::lock_guard<std::mutex> lk(self->udp_mu_);
        self->udp_receipts_[{pcb->local_port, dst_ip_be}] = std::move(rec);
    }
    pbuf_free(p);
}

bool UpperTesterServer::triggerSendUdp(std::uint16_t src_port,
                                       std::uint32_t dst_ip_be,
                                       std::uint16_t dst_port,
                                       const std::uint8_t *payload,
                                       std::uint16_t payload_len,
                                       std::uint32_t src_ip_override_be) {
    bool ok = false;
    err_t err = ERR_MEM;
    LOCK_TCPIP_CORE();
    struct udp_pcb *pcb = udp_new();
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, payload_len, PBUF_RAM);
    if (pcb != nullptr && p != nullptr &&
        udp_bind(pcb, IP_ANY_TYPE, src_port) == ERR_OK) {
        if (payload_len > 0) {
            pbuf_take(p, payload, payload_len);
        }
        ip_addr_t dst;
        ip_addr_set_ip4_u32_val(dst, dst_ip_be);
        ip_addr_t src;
        if (src_ip_override_be != 0) {
            // §4.6.5.5 UI_07 caller-specified source. No local-address
            // validation on purpose: udp_sendto_if_src emits whatever
            // source the caller names, which is the entire point of the
            // spec axis (the Linux server gets the same effect from
            // binding to a netns alias).
            ip_addr_set_ip4_u32_val(src, src_ip_override_be);
        } else {
            ip_addr_set_ip4_u32_val(
                src, ip4_addr_get_u32(netif_ip4_addr(netif_default)));
        }
        err = udp_sendto_if_src(pcb, p, &dst, dst_port, netif_default, &src);
        ok = (err == ERR_OK);
    }
    if (p != nullptr) pbuf_free(p);
    if (pcb != nullptr) udp_remove(pcb);
    UNLOCK_TCPIP_CORE();
    if (!ok) {
        std::fprintf(stderr,
                     "tc8-lwip-ut: TriggerSendUdp from port %u failed "
                     "(err %d)\n",
                     src_port, static_cast<int>(err));
    }
    return ok;
}

std::uint8_t UpperTesterServer::createUdpReceivePorts(std::uint8_t count) {
    std::uint8_t created = 0;
    LOCK_TCPIP_CORE();
    for (std::uint8_t i = 0; i < count; ++i) {
        struct udp_pcb *pcb = udp_new();
        if (pcb == nullptr) {
            break;
        }
        // Port 0 => udp_bind picks a fresh ephemeral port, mirroring
        // the Linux bind(INADDR_ANY, 0). No recv callback on purpose:
        // udp_input frees datagrams for a callback-less pcb, same as
        // the Linux server never reading the fds.
        if (udp_bind(pcb, IP_ANY_TYPE, 0) != ERR_OK) {
            udp_remove(pcb);
            break;
        }
        udp_receive_ports_.push_back(pcb);
        ++created;
    }
    UNLOCK_TCPIP_CORE();
    if (created < count) {
        std::fprintf(stderr,
                     "tc8-lwip-ut: CreateUdpReceivePorts created %u of %u "
                     "(udp pcb pool exhausted? see MEMP_NUM_UDP_PCB)\n",
                     created, count);
    }
    return created;
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

    case ut::OpGetReceivedUdp: {
        // Params: <listen_port:u16> <expected_dst_ip:u32>
        if (n < 2 + 2 + 4) {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        const std::uint16_t listen_port     = readBe16(buf + 2);
        const std::uint32_t expected_dst_be = lwip_htonl(readBe32(buf + 4));
        bool found = false;
        UdpReceipt rec;
        {
            std::lock_guard<std::mutex> lk(udp_mu_);
            auto it = udp_receipts_.find({listen_port, expected_dst_be});
            if (it != udp_receipts_.end()) {
                rec   = it->second;
                found = true;
            }
        }
        if (found) {
            body.push_back(0x01);  // received
            appendNboIp(body, rec.src_ip_be);
            appendBe16(body, rec.src_port);
            appendBe16(body, static_cast<std::uint16_t>(
                                 std::min<std::size_t>(rec.original_len,
                                                       0xFFFFu)));
            body.insert(body.end(), rec.payload.begin(), rec.payload.end());
        } else {
            body.push_back(0x00);  // not received
        }
        respond(fd, peer, opcode, req_id, ut::kStatusOk, body);
        return;
    }

    case ut::OpTriggerSendUdp: {
        // Params: <src_port:u16> <dst_ip:u32> <dst_port:u16>
        //         <payload_len:u16> <payload[]>
        //         [<src_ip_override_be:u32>]   // optional trailer
        // Strict size bracketing, same as the Linux parser: exactly
        // 12+payload_len (legacy) or 12+payload_len+4 (override).
        if (n < 2 + 2 + 4 + 2 + 2) {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        const std::uint16_t src_port    = readBe16(buf + 2);
        const std::uint32_t dst_ip_be   = lwip_htonl(readBe32(buf + 4));
        const std::uint16_t dst_port    = readBe16(buf + 8);
        const std::uint16_t payload_len = readBe16(buf + 10);
        const std::size_t legacy_size   = 12u + payload_len;
        const std::size_t override_size = legacy_size + 4u;
        std::uint32_t src_ip_override_be = 0;
        if (static_cast<std::size_t>(n) == legacy_size) {
            // Legacy caller — default to the primary iface address.
        } else if (static_cast<std::size_t>(n) == override_size) {
            src_ip_override_be =
                lwip_htonl(readBe32(buf + 12u + payload_len));
        } else {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        const bool ok = triggerSendUdp(src_port, dst_ip_be, dst_port,
                                       buf + 12, payload_len,
                                       src_ip_override_be);
        respond(fd, peer, opcode, req_id,
                ok ? ut::kStatusOk : ut::kStatusSendFailed, body);
        return;
    }

    case ut::OpCreateUdpReceivePorts: {
        // Params: <count:u8>. kStatusOk even when created < count — the
        // SCXML pass guard verdicts on the count match, not the status.
        if (n < 2 + 1) {
            respond(fd, peer, opcode, req_id, ut::kStatusMalformed, body);
            return;
        }
        body.push_back(createUdpReceivePorts(buf[2]));
        respond(fd, peer, opcode, req_id, ut::kStatusOk, body);
        return;
    }

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
    startUdpDataListener();
    std::fprintf(stderr,
                 "tc8-lwip-ut: serving on UDP port %u (opcodes 0x01..0x0B + "
                 "0x14 + OpPing; max_opcode reported 0x%02X)\n",
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

namespace {
UpperTesterServer *g_server = nullptr;
}  // namespace

void StartUpperTesterServer(std::uint32_t dut_ip_be) {
    // Leaked deliberately: the server lives for the process lifetime
    // and the fixture tears the process down (SIGTERM, SIGKILL
    // backstop) via the topology conf.
    auto *server = new UpperTesterServer(dut_ip_be);
    g_server = server;
    std::thread([server] { server->run(); }).detach();
}

void AbortUpperTesterSlots() {
    if (g_server != nullptr) {
        g_server->abortAllSlots();
    }
}

}  // namespace tc8::lwip_dut
