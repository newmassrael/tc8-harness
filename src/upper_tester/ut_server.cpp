#include "upper_tester/ut_server.h"

#include <chrono>
#include <cstring>
#include <utility>

namespace tc8::ut {

namespace {

// UT requests are bounded by kMaxPayload + small headers; the data listener
// must accept §4.6.5.4 UDP_FIELDS_12's 65 507 B max-length datagram.
constexpr std::size_t kUtRequestBufferLen = 2048;
constexpr std::size_t kDataBufferLen = 65536;

// Wake interval for the acceptor loop's readable wait — bounds how fast it
// notices the stop flag. Matches the listener sockets' 200 ms recv timeout.
constexpr int kAcceptWaitUs = 200 * 1000;

// Bounded active-connect budget. The old connector issued an unbounded blocking
// connect; the spec active-open cases (BASICS_06+) observe the DUT's SYN and
// query the result shortly after, so a few seconds covers any real handshake
// while a refused connect returns immediately. Re-verify under netns at LIVE.
constexpr int kConnectTimeoutMs = 5000;

// §4.6.5.5 UI-report corruption sentinels (kAppFaultReport* / kAppFaultMiscountPorts). XOR by
// a nonzero mask guarantees the reported field differs from the value the tester sent — the
// report-fault analog of lwip_egress_fault.cpp's kChecksumFlip idiom — so the matching UI_0x
// `_neg`'s "!= expected" pass predicate is always reachable. The port-count fault over-reports
// by one (the bound count is 10; +1 = 11 != 10).
constexpr std::uint16_t kReportSrcPortFlip   = 0xFFFFU;  // UI_03 src port
constexpr std::uint8_t  kReportSrcIpByteFlip = 0xFFU;    // UI_04 src IP low byte
constexpr std::uint8_t  kReportPayloadFlip   = 0xFFU;    // UI_02 first data octet
constexpr std::uint8_t  kReportPortOverCount = 1U;       // UI_01 over-report

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

// Wire IPv4 (4 bytes MSB-first) <-> the host's network-byte-order address word
// (sockaddr_in::sin_addr.s_addr layout). memcpy of the wire bytes is both
// endian-portable and byte-identical to the explicit-shift form on the LE host.
std::uint32_t ipFromWire(const std::uint8_t *p) {
    std::uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

void appendIp(std::vector<std::uint8_t> &b, std::uint32_t ip_be) {
    std::uint8_t t[4];
    std::memcpy(t, &ip_be, 4);
    b.insert(b.end(), t, t + 4);
}

// Class D (224.0.0.0/4): the first wire octet is byte 0 of the NBO word.
bool isMulticastV4(std::uint32_t addr_be) {
    std::uint8_t first = 0;
    std::memcpy(&first, &addr_be, 1);
    return first >= 224 && first <= 239;
}

}  // namespace

UpperTesterServer::UpperTesterServer(std::unique_ptr<net::SocketBackend> backend,
                                     std::unique_ptr<StackProbe> probe)
    : backend_(std::move(backend)), probe_(std::move(probe)) {
    installBuiltins();
}

UpperTesterServer::~UpperTesterServer() {
    stop();
}

void UpperTesterServer::installBuiltins() {
    // The dispatch table is the single source for admission, the capability
    // bitmap, and the OpPing contiguous-top. Platform-specific opcode families
    // (autoconf/DHCP 0x0C..0x12, ARP conditioning 0x17) join it via
    // registerOpcode() — the core itself only knows the cross-platform set.
    auto bind = [this](std::uint8_t opcode,
                       void (UpperTesterServer::*fn)(const std::uint8_t *, std::size_t,
                                                     std::uint8_t &, std::vector<std::uint8_t> &)) {
        handlers_[opcode] = [this, fn](const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                       std::vector<std::uint8_t> &body) { (this->*fn)(p, n, st, body); };
    };
    bind(OpGetReceivedUdp, &UpperTesterServer::handleGetReceivedUdp);
    bind(OpTriggerSendUdp, &UpperTesterServer::handleTriggerSendUdp);
    bind(OpOpenTcpSocket, &UpperTesterServer::handleOpenTcpSocket);
    bind(OpCloseTcpSocket, &UpperTesterServer::handleCloseTcpSocket);
    bind(OpQueryTcpEstablished, &UpperTesterServer::handleQueryTcpEstablished);
    bind(OpSendTcpData, &UpperTesterServer::handleSendTcpData);
    bind(OpReceiveTcpData, &UpperTesterServer::handleReceiveTcpData);
    bind(OpShutdownTcpSocketWr, &UpperTesterServer::handleShutdownTcpSocketWr);
    bind(OpAbortTcpSocket, &UpperTesterServer::handleAbortTcpSocket);
    bind(OpSendTcpDataPattern, &UpperTesterServer::handleSendTcpDataPattern);
    bind(OpReceiveTcpDataOob, &UpperTesterServer::handleReceiveTcpDataOob);
    bind(OpQueryTcpInfo, &UpperTesterServer::handleQueryTcpInfo);
    bind(OpCreateUdpReceivePorts, &UpperTesterServer::handleCreateUdpReceivePorts);
    bind(OpPing, &UpperTesterServer::handlePing);
    bind(OpQueryCapabilities, &UpperTesterServer::handleQueryCapabilities);
}

void UpperTesterServer::registerOpcode(std::uint8_t opcode, OpcodeHandler handler) {
    handlers_[opcode] = std::move(handler);
}

void UpperTesterServer::setAppFaultFlavor(std::uint8_t flavor) {
    app_fault_flavor_.store(flavor, std::memory_order_relaxed);
}

bool UpperTesterServer::start(std::uint32_t iface_ip_be, std::uint32_t iface_bcast_be,
                              std::uint16_t ut_port, std::uint16_t data_port) {
    iface_ip_be_ = iface_ip_be;
    iface_bcast_be_ = iface_bcast_be;
    data_port_ = data_port;

    // Derive the capability surface from the (now-complete) handler table.
    capability_bitmap_ = {};
    for (const auto &kv : handlers_) {
        capability_bitmap_[kv.first / 8u] |= static_cast<std::uint8_t>(1u << (kv.first % 8u));
    }
    ping_max_opcode_ = 0;
    for (std::uint8_t op = 1; handlers_.count(op) != 0; ++op) {
        ping_max_opcode_ = op;
    }

    data_fd_ = probe_->openOriginalDstListenerV4(data_port);
    if (data_fd_ < 0) {
        return false;
    }
    ut_fd_ = backend_->createUdp();
    if (ut_fd_ < 0) {
        backend_->closeFd(data_fd_);
        data_fd_ = -1;
        return false;
    }
    backend_->setReuseAddr(ut_fd_);
    backend_->setRecvTimeoutMs(ut_fd_, 200);  // wake to check stop_requested_
    if (!backend_->bindV4(ut_fd_, /*addr_be=*/0, ut_port)) {
        backend_->closeFd(ut_fd_);
        backend_->closeFd(data_fd_);
        ut_fd_ = -1;
        data_fd_ = -1;
        return false;
    }

    stop_requested_.store(false);
    data_thread_ = std::thread([this] { dataListenerLoop(); });
    ut_thread_ = std::thread([this] { utServerLoop(); });
    return true;
}

void UpperTesterServer::stop(bool abort) {
    stop_requested_.store(true);
    if (data_thread_.joinable()) data_thread_.join();
    if (ut_thread_.joinable()) ut_thread_.join();
    if (data_fd_ >= 0) {
        backend_->closeFd(data_fd_);
        data_fd_ = -1;
    }
    if (ut_fd_ >= 0) {
        backend_->closeFd(ut_fd_);
        ut_fd_ = -1;
    }

    // Tear down any TCP sessions still alive. Extract under the lock, then
    // signal / join / close outside it so an acceptor finishing under tcp_mu_
    // cannot deadlock the join (mirrors tearDownSlot).
    std::map<std::uint8_t, std::unique_ptr<TcpSlot>> slots;
    {
        std::lock_guard<std::mutex> lk(tcp_mu_);
        slots.swap(tcp_slots_);
    }
    for (auto &kv : slots) {
        TcpSlot *s = kv.second.get();
        s->stop.store(true);
        if (s->kind == TcpKind::Active && s->accepted_fd >= 0) {
            backend_->shutdown(s->accepted_fd, 2);  // unblock a connector mid-connect
        }
        if (s->worker.joinable()) s->worker.join();
        if (s->accepted_fd >= 0) {
            if (abort) {
                backend_->closeWithAbort(s->accepted_fd);  // RST the leaked connection
            } else {
                backend_->closeFd(s->accepted_fd);
            }
        }
        if (s->listen_fd >= 0) backend_->closeFd(s->listen_fd);
    }

    std::lock_guard<std::mutex> lk(udp_receive_ports_mu_);
    for (int fd : udp_receive_ports_) {
        if (fd >= 0) backend_->closeFd(fd);
    }
    udp_receive_ports_.clear();
}

void UpperTesterServer::utServerLoop() {
    std::uint8_t buf[kUtRequestBufferLen];
    while (!stop_requested_.load()) {
        net::Endpoint peer;
        const int n = backend_->recvFromV4(ut_fd_, buf, sizeof(buf), peer);
        if (n < 2) {
            continue;  // timeout or too short to carry opcode + req_id
        }
        const std::size_t avail =
            (static_cast<std::size_t>(n) < sizeof(buf)) ? static_cast<std::size_t>(n) : sizeof(buf);
        const std::uint8_t opcode = buf[0];
        const std::uint8_t req_id = buf[1];
        // Never respond to our own responses (amplification guard).
        if ((opcode & kResponseBit) != 0) {
            continue;
        }
        std::uint8_t status = kStatusOk;
        std::vector<std::uint8_t> body;
        dispatch(opcode, buf + 2, avail - 2, status, body);
        sendResponse(peer, static_cast<std::uint8_t>(opcode | kResponseBit), req_id, status, body);
    }
}

void UpperTesterServer::dispatch(std::uint8_t opcode, const std::uint8_t *params, std::size_t len,
                                 std::uint8_t &status, std::vector<std::uint8_t> &body) {
    const auto it = handlers_.find(opcode);
    if (it == handlers_.end()) {
        status = kStatusUnknownOpcode;  // not in the table = not advertised, not served
        return;
    }
    it->second(params, len, status, body);
}

void UpperTesterServer::sendResponse(const net::Endpoint &peer, std::uint8_t response_opcode,
                                     std::uint8_t req_id, std::uint8_t status,
                                     const std::vector<std::uint8_t> &body) {
    std::vector<std::uint8_t> frame;
    frame.reserve(3 + body.size());
    frame.push_back(response_opcode);
    frame.push_back(req_id);
    frame.push_back(status);
    frame.insert(frame.end(), body.begin(), body.end());
    backend_->sendToV4(ut_fd_, frame.data(), frame.size(), peer);
}

void UpperTesterServer::dataListenerLoop() {
    std::vector<std::uint8_t> buf(kDataBufferLen);
    while (!stop_requested_.load()) {
        net::Endpoint src;
        std::uint32_t orig_dst_be = 0;
        const int n = probe_->recvWithOriginalDstV4(data_fd_, buf.data(), buf.size(), src, orig_dst_be);
        if (n < 0) {
            continue;  // timeout — re-check stop
        }
        const std::uint8_t app_flavor = app_fault_flavor_.load(std::memory_order_relaxed);
        // §4.4.4.5 ADDRESSING_02: silently discard directed-broadcast at the
        // application layer (limited broadcast 255.255.255.255 is kept). The
        // kAppFaultAcceptDirectedBroadcast app fault skips this discard so a buggy DUT
        // counts the directed broadcast it must drop — the reception ipv4_addressing_02
        // proves absent (armed lwIP-only via OpSetAppFlavor).
        if (app_flavor != kAppFaultAcceptDirectedBroadcast && iface_bcast_be_ != 0 &&
            orig_dst_be == iface_bcast_be_) {
            continue;
        }
        // §4.6.5.6 UDP_INTRODUCTION_02: silently discard multicast. The
        // kAppFaultAcceptMulticast app fault skips this discard so a buggy DUT counts
        // the multicast it must drop — the reception udp_introduction_02 proves absent
        // (armed lwIP-only via OpSetAppFlavor; lwIP delivers multicast to the socket
        // with LWIP_IGMP off, so the discard here is the real drop point).
        if (app_flavor != kAppFaultAcceptMulticast && isMulticastV4(orig_dst_be)) {
            continue;
        }
        ReceiveRecord rec;
        rec.src_ip = src.addr_be;
        rec.dst_ip = orig_dst_be;
        rec.src_port = src.port;
        rec.dst_port = data_port_;
        rec.payload.assign(buf.data(), buf.data() + n);
        rec.populated = true;
        // §4.6.5.5 UDP User-Interface report corruption: the datagram arrived correctly,
        // but a buggy DUT surfaces a wrong field in the GetReceivedUdp Confirmation. This
        // is the only faithful site — the stack delivered the right metadata, so the
        // defect is the receive operation's reporting of it. Armed lwIP-only via
        // OpSetAppFlavor; each UI_0x _neg passes only when the corrupted field is observed.
        if (app_flavor == kAppFaultReportWrongSrcPort) {
            rec.src_port ^= kReportSrcPortFlip;  // != the tester's src port (UI_03)
        } else if (app_flavor == kAppFaultReportWrongSrcIp) {
            rec.src_ip ^= kReportSrcIpByteFlip;  // != the tester's src IP (UI_04)
        } else if (app_flavor == kAppFaultReportWrongPayload && !rec.payload.empty()) {
            rec.payload[0] ^= kReportPayloadFlip;  // first data octet != what the tester sent (UI_02)
        } else if (app_flavor == kAppFaultReportWrongLength) {
            rec.payload.resize(rec.payload.size() + 1U);  // report length+1 != the size sent (FIELDS_12)
        }
        std::lock_guard<std::mutex> lk(log_mu_);
        last_receipt_ = std::move(rec);
    }
}

// ---- opcode handlers --------------------------------------------------------

void UpperTesterServer::handleGetReceivedUdp(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                             std::vector<std::uint8_t> &body) {
    if (n < 2 + 4) {  // listen_port:u16 + expected_dst_ip:u32
        st = kStatusMalformed;
        return;
    }
    const std::uint16_t listen_port = readU16(p);
    const std::uint32_t expected_dst_be = ipFromWire(p + 2);
    const auto rec = lookupReceipt(listen_port, expected_dst_be);
    if (rec.has_value()) {
        body.push_back(0x01);  // received
        appendIp(body, rec->src_ip);
        writeBe16(body, rec->src_port);
        // payload_len carries the ORIGINAL receipt length (capped u16) — §4.6.5.4
        // UDP_FIELDS_12 verdicts on it — while the trailer bytes stay truncated to
        // kMaxPayload so the Confirmation datagram stays under MTU.
        const std::uint16_t plen =
            static_cast<std::uint16_t>(rec->payload.size() > 0xFFFFu ? 0xFFFFu : rec->payload.size());
        writeBe16(body, plen);
        const std::size_t copy_len =
            rec->payload.size() < kMaxPayload ? rec->payload.size() : kMaxPayload;
        body.insert(body.end(), rec->payload.begin(),
                    rec->payload.begin() + static_cast<std::ptrdiff_t>(copy_len));
    } else {
        body.push_back(0x00);  // not received
    }
}

void UpperTesterServer::handleTriggerSendUdp(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                             std::vector<std::uint8_t> &body) {
    (void)body;
    // src_port:u16 + dst_ip:u32 + dst_port:u16 + payload_len:u16 + payload[]
    //   + optional src_ip_override:u32 (append-only trailer).
    if (n < 10) {
        st = kStatusMalformed;
        return;
    }
    const std::uint16_t src_port = readU16(p);
    const std::uint32_t dst_ip_be = ipFromWire(p + 2);
    const std::uint16_t dst_port = readU16(p + 6);
    const std::uint16_t payload_len = readU16(p + 8);
    const std::size_t legacy = 10u + payload_len;
    const std::size_t with_override = legacy + 4u;
    std::uint32_t src_override_be = 0;
    if (n == legacy) {
        // legacy caller — default source binding to the primary iface
    } else if (n == with_override) {
        src_override_be = ipFromWire(p + 10 + payload_len);
    } else {
        st = kStatusMalformed;
        return;
    }
    const bool ok =
        triggerSendUdp(src_port, dst_ip_be, dst_port, p + 10, payload_len, src_override_be);
    st = ok ? kStatusOk : kStatusSendFailed;
}

void UpperTesterServer::handleOpenTcpSocket(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                            std::vector<std::uint8_t> &body) {
    if (n < 3) {  // type:u8 + local_port:u16
        st = kStatusMalformed;
        return;
    }
    const std::uint8_t type = p[0];
    const std::uint16_t local_port = readU16(p + 1);
    if (type == kSocketTypePassive) {
        const auto sid = openTcpPassive(local_port);
        if (!sid.has_value()) {
            st = kStatusBindFailed;
            return;
        }
        body.push_back(*sid);
    } else if (type == kSocketTypeActive) {
        if (n < 3 + 4 + 2) {  // + remote_ip:u32 + remote_port:u16
            st = kStatusMalformed;
            return;
        }
        const std::uint32_t remote_ip_be = ipFromWire(p + 3);
        const std::uint16_t remote_port = readU16(p + 7);
        const auto sid = openTcpActive(local_port, remote_ip_be, remote_port);
        if (!sid.has_value()) {
            st = kStatusConnectFailed;
            return;
        }
        body.push_back(*sid);
    } else {
        st = kStatusMalformed;
    }
}

void UpperTesterServer::handleCloseTcpSocket(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                             std::vector<std::uint8_t> &body) {
    (void)body;
    if (n < 1) {
        st = kStatusMalformed;
        return;
    }
    st = tearDownSlot(p[0], /*abort=*/false) ? kStatusOk : kStatusUnknownSocket;
}

void UpperTesterServer::handleQueryTcpEstablished(const std::uint8_t *p, std::size_t n,
                                                  std::uint8_t &st, std::vector<std::uint8_t> &body) {
    if (n < 1) {
        st = kStatusMalformed;
        return;
    }
    const std::uint8_t socket_id = p[0];
    if (!slotExists(socket_id)) {
        st = kStatusUnknownSocket;
        return;
    }
    // No accepted fd yet => the listener is in LISTEN, not ESTABLISHED.
    std::uint8_t established = 0;
    const int fd = slotConnFd(socket_id);
    if (fd >= 0) {
        TcpInfo info;
        if (probe_->queryTcpInfo(fd, info) && info.state == kTcpStateEstablished) {
            established = 1;
        }
    }
    body.push_back(established);
}

void UpperTesterServer::handleSendTcpData(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                          std::vector<std::uint8_t> &body) {
    (void)body;
    if (n < 3) {  // socket_id:u8 + payload_len:u16
        st = kStatusMalformed;
        return;
    }
    const std::uint8_t socket_id = p[0];
    const std::uint16_t payload_len = readU16(p + 1);
    if (n < 3u + payload_len) {
        st = kStatusMalformed;
        return;
    }
    if (!slotExists(socket_id)) {
        st = kStatusUnknownSocket;
        return;
    }
    const int fd = slotConnFd(socket_id);
    bool ok = false;
    if (fd >= 0) {
        std::uint16_t written = 0;
        ok = true;
        while (written < payload_len) {
            const int rc = backend_->send(fd, p + 3 + written, payload_len - written);
            if (rc <= 0) {  // error / peer close (the seam hides errno; no EINTR retry)
                ok = false;
                break;
            }
            written = static_cast<std::uint16_t>(written + rc);
        }
    }
    st = ok ? kStatusOk : kStatusSendFailed;
}

void UpperTesterServer::handleReceiveTcpData(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                             std::vector<std::uint8_t> &body) {
    if (n < 5) {  // socket_id:u8 + expected_len:u16 + timeout_ms:u16
        st = kStatusMalformed;
        return;
    }
    const std::uint8_t socket_id = p[0];
    const std::uint16_t expected_len = readU16(p + 1);
    const std::uint16_t timeout_ms = readU16(p + 3);
    if (!slotExists(socket_id)) {
        st = kStatusUnknownSocket;
        return;
    }
    const int fd = slotConnFd(socket_id);
    std::vector<std::uint8_t> bytes;
    if (fd >= 0 && expected_len != 0) {
        bytes.resize(expected_len);
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        std::uint16_t total = 0;
        while (total < expected_len) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) break;
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            backend_->setRecvTimeoutMs(fd, static_cast<int>(remaining.count()));
            const int rc = backend_->recv(fd, bytes.data() + total, expected_len - total);
            if (rc > 0) {
                total = static_cast<std::uint16_t>(total + rc);
                continue;
            }
            break;  // peer close (0) or timeout/error (<0)
        }
        bytes.resize(total);
    }
    writeBe16(body, static_cast<std::uint16_t>(bytes.size()));
    body.insert(body.end(), bytes.begin(), bytes.end());
}

void UpperTesterServer::handleShutdownTcpSocketWr(const std::uint8_t *p, std::size_t n,
                                                  std::uint8_t &st, std::vector<std::uint8_t> &body) {
    (void)body;
    if (n < 1) {
        st = kStatusMalformed;
        return;
    }
    const int fd = slotConnFd(p[0]);  // -1 if unknown slot or no accepted fd
    const bool ok = (fd >= 0) && backend_->shutdown(fd, 1);  // 1 = SHUT_WR
    st = ok ? kStatusOk : kStatusUnknownSocket;
}

void UpperTesterServer::handleAbortTcpSocket(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                             std::vector<std::uint8_t> &body) {
    (void)body;
    if (n < 1) {
        st = kStatusMalformed;
        return;
    }
    st = tearDownSlot(p[0], /*abort=*/true) ? kStatusOk : kStatusUnknownSocket;
}

void UpperTesterServer::handleSendTcpDataPattern(const std::uint8_t *p, std::size_t n,
                                                 std::uint8_t &st, std::vector<std::uint8_t> &body) {
    (void)body;
    if (n < 4) {  // socket_id:u8 + pattern:u8 + total_len:u16
        st = kStatusMalformed;
        return;
    }
    const std::uint8_t socket_id = p[0];
    const std::uint8_t pattern = p[1];
    const std::uint16_t total_len = readU16(p + 2);
    if (!slotExists(socket_id)) {
        st = kStatusUnknownSocket;
        return;
    }
    const int fd = slotConnFd(socket_id);
    bool ok = false;
    if (fd >= 0) {
        if (total_len == 0) {
            ok = true;
        } else {
            const std::vector<std::uint8_t> bulk(total_len, pattern);
            std::uint16_t written = 0;
            ok = true;
            while (written < total_len) {
                const int rc = backend_->send(fd, bulk.data() + written, total_len - written);
                if (rc <= 0) {
                    ok = false;
                    break;
                }
                written = static_cast<std::uint16_t>(written + rc);
            }
        }
    }
    st = ok ? kStatusOk : kStatusSendFailed;
}

void UpperTesterServer::handleReceiveTcpDataOob(const std::uint8_t *p, std::size_t n,
                                                std::uint8_t &st, std::vector<std::uint8_t> &body) {
    if (n < 5) {  // socket_id:u8 + expected_len:u16 + timeout_ms:u16
        st = kStatusMalformed;
        return;
    }
    const std::uint8_t socket_id = p[0];
    const std::uint16_t expected_len = readU16(p + 1);
    const std::uint16_t timeout_ms = readU16(p + 3);
    if (!slotExists(socket_id)) {
        st = kStatusUnknownSocket;
        return;
    }
    const int fd = slotConnFd(socket_id);
    std::vector<std::uint8_t> bytes;
    if (fd >= 0 && expected_len != 0) {
        bytes.resize(expected_len);
        const int rc = probe_->recvOob(fd, bytes.data(), expected_len, timeout_ms);
        bytes.resize(rc > 0 ? static_cast<std::size_t>(rc) : 0);
    }
    writeBe16(body, static_cast<std::uint16_t>(bytes.size()));
    body.insert(body.end(), bytes.begin(), bytes.end());
}

void UpperTesterServer::handleQueryTcpInfo(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                           std::vector<std::uint8_t> &body) {
    if (n < 1) {
        st = kStatusMalformed;
        return;
    }
    const std::uint8_t socket_id = p[0];
    if (!slotExists(socket_id)) {
        st = kStatusUnknownSocket;
        return;
    }
    const int fd = slotConnFd(socket_id);
    TcpInfo info;
    if (fd < 0 || !probe_->queryTcpInfo(fd, info)) {
        st = kStatusUnknownSocket;  // no kernel state to report
        return;
    }
    body.push_back(info.state);
    writeBe32(body, info.rto_us);
    body.push_back(info.retransmits);
    writeBe32(body, info.unacked);
}

void UpperTesterServer::handleCreateUdpReceivePorts(const std::uint8_t *p, std::size_t n,
                                                    std::uint8_t &st,
                                                    std::vector<std::uint8_t> &body) {
    if (n < 1) {
        st = kStatusMalformed;
        return;
    }
    body.push_back(createUdpReceivePorts(p[0]));
}

void UpperTesterServer::handlePing(const std::uint8_t *p, std::size_t n, std::uint8_t &st,
                                   std::vector<std::uint8_t> &body) {
    (void)p;
    (void)n;
    (void)st;
    body.push_back(ping_max_opcode_);  // contiguous top, derived from the table
}

void UpperTesterServer::handleQueryCapabilities(const std::uint8_t *p, std::size_t n,
                                                std::uint8_t &st, std::vector<std::uint8_t> &body) {
    (void)p;
    (void)n;
    (void)st;
    body.push_back(static_cast<std::uint8_t>(capability_bitmap_.size()));
    body.insert(body.end(), capability_bitmap_.begin(), capability_bitmap_.end());
}

// ---- TCP session backend ----------------------------------------------------

std::optional<std::uint8_t> UpperTesterServer::openTcpPassive(std::uint16_t local_port) {
    const int fd = backend_->createTcp();
    if (fd < 0) return std::nullopt;
    backend_->setReuseAddr(fd);
    if (!backend_->bindV4(fd, /*addr_be=*/0, local_port)) {
        backend_->closeFd(fd);
        return std::nullopt;
    }
    // backlog 1: §4.8.6.1 BASICS need a single connection per listener.
    if (!backend_->listen(fd, 1)) {
        backend_->closeFd(fd);
        return std::nullopt;
    }
    auto slot = std::make_unique<TcpSlot>();
    slot->kind = TcpKind::Passive;
    slot->listen_fd = fd;
    slot->local_port = local_port;

    std::lock_guard<std::mutex> lk(tcp_mu_);
    const std::uint8_t sid = next_tcp_socket_id_++;
    if (next_tcp_socket_id_ == 0U) next_tcp_socket_id_ = 1U;  // skip 0
    TcpSlot *raw = slot.get();
    tcp_slots_.emplace(sid, std::move(slot));
    raw->worker = std::thread([this, raw] { tcpAcceptorLoop(raw); });
    return sid;
}

std::optional<std::uint8_t> UpperTesterServer::openTcpActive(std::uint16_t local_port,
                                                             std::uint32_t remote_ip_be,
                                                             std::uint16_t remote_port) {
    const int fd = backend_->createTcp();
    if (fd < 0) return std::nullopt;
    backend_->setReuseAddr(fd);
    // Bind the source to (iface_ip, local_port) so the DUT's SYN carries a
    // deterministic source endpoint the tester can filter on.
    if (!backend_->bindV4(fd, iface_ip_be_, local_port)) {
        backend_->closeFd(fd);
        return std::nullopt;
    }
    auto slot = std::make_unique<TcpSlot>();
    slot->kind = TcpKind::Active;
    slot->listen_fd = -1;
    slot->accepted_fd = fd;
    slot->local_port = local_port;
    slot->remote_ip_be = remote_ip_be;
    slot->remote_port = remote_port;

    std::lock_guard<std::mutex> lk(tcp_mu_);
    const std::uint8_t sid = next_tcp_socket_id_++;
    if (next_tcp_socket_id_ == 0U) next_tcp_socket_id_ = 1U;
    TcpSlot *raw = slot.get();
    tcp_slots_.emplace(sid, std::move(slot));
    raw->worker = std::thread(
        [this, raw, remote_ip_be, remote_port] { tcpConnectorLoop(raw, remote_ip_be, remote_port); });
    return sid;
}

bool UpperTesterServer::tearDownSlot(std::uint8_t socket_id, bool abort) {
    std::unique_ptr<TcpSlot> owned;
    {
        std::lock_guard<std::mutex> lk(tcp_mu_);
        const auto it = tcp_slots_.find(socket_id);
        if (it == tcp_slots_.end()) {
            return false;
        }
        owned = std::move(it->second);
        tcp_slots_.erase(it);
    }
    // Outside tcp_mu_: an acceptor finishing under the lock cannot deadlock the
    // join. Active connectors block in connect(); shutdown(RDWR) unblocks them.
    owned->stop.store(true);
    if (owned->kind == TcpKind::Active && owned->accepted_fd >= 0) {
        backend_->shutdown(owned->accepted_fd, 2);  // SHUT_RDWR
    }
    if (owned->worker.joinable()) owned->worker.join();
    if (owned->accepted_fd >= 0) {
        if (abort) {
            backend_->closeWithAbort(owned->accepted_fd);  // RST + (active) TIME-WAIT destroy
        } else {
            backend_->closeFd(owned->accepted_fd);
        }
    }
    if (owned->listen_fd >= 0) {
        backend_->closeFd(owned->listen_fd);
    }
    return true;
}

bool UpperTesterServer::slotExists(std::uint8_t socket_id) const {
    std::lock_guard<std::mutex> lk(tcp_mu_);
    return tcp_slots_.find(socket_id) != tcp_slots_.end();
}

int UpperTesterServer::slotConnFd(std::uint8_t socket_id) const {
    std::lock_guard<std::mutex> lk(tcp_mu_);
    const auto it = tcp_slots_.find(socket_id);
    return it == tcp_slots_.end() ? -1 : it->second->accepted_fd;
}

void UpperTesterServer::tcpAcceptorLoop(TcpSlot *slot) {
    // One-shot acceptor: wait for a connection, store the accepted fd, exit.
    while (!stop_requested_.load() && !slot->stop.load()) {
        const int sr = backend_->waitReadable(slot->listen_fd, kAcceptWaitUs);
        if (sr < 0) return;     // fd closed under us / fatal
        if (sr == 0) continue;  // timeout — re-check stop flags
        net::Endpoint client;
        const int conn = backend_->accept(slot->listen_fd, client);
        if (conn < 0) continue;  // spurious wakeup
        // Publish accepted_fd under tcp_mu_ — readers (slotConnFd) hold it too,
        // so the worker write races neither them nor the post-join teardown.
        std::lock_guard<std::mutex> lk(tcp_mu_);
        slot->accepted_fd = conn;
        return;
    }
}

void UpperTesterServer::tcpConnectorLoop(TcpSlot *slot, std::uint32_t remote_ip_be,
                                         std::uint16_t remote_port) {
    // Active open on a worker thread so the UT reply is sent the moment the bind
    // succeeds — the tester's wall-time tracks the SYN handshake, not the RPC.
    // The connect outcome is observed later via OpQueryTcpEstablished; the bound
    // connect records the 4-tuple a later abort needs to destroy a TIME-WAIT.
    net::Endpoint dst;
    dst.addr_be = remote_ip_be;
    dst.port = remote_port;
    backend_->connectBoundedV4(slot->accepted_fd, dst, kConnectTimeoutMs);
}

// ---- UDP backend ------------------------------------------------------------

bool UpperTesterServer::triggerSendUdp(std::uint16_t src_port, std::uint32_t dst_ip_be,
                                       std::uint16_t dst_port, const std::uint8_t *payload,
                                       std::uint16_t payload_len, std::uint32_t src_ip_override_be) {
    const int fd = backend_->createUdp();
    if (fd < 0) return false;
    backend_->setReuseAddr(fd);
    backend_->setBroadcast(fd);
    // UI_07: a non-zero override pins the source to a netns-configured alias; a
    // non-local override fails bind => kStatusSendFailed. 0 falls through to the
    // primary iface IP, preserving FRAGMENTS_05 / UI_01..06 wire shape.
    const std::uint32_t bind_ip_be = (src_ip_override_be != 0U) ? src_ip_override_be : iface_ip_be_;
    if (!backend_->bindV4(fd, bind_ip_be, src_port)) {
        backend_->closeFd(fd);
        return false;
    }
    net::Endpoint dst;
    dst.addr_be = dst_ip_be;
    dst.port = dst_port;
    const int rc = backend_->sendToV4(fd, payload, payload_len, dst);
    backend_->closeFd(fd);
    return rc == static_cast<int>(payload_len);
}

std::uint8_t UpperTesterServer::createUdpReceivePorts(std::uint8_t count) {
    std::uint8_t actual = 0;
    std::lock_guard<std::mutex> lk(udp_receive_ports_mu_);
    for (std::uint8_t i = 0; i < count; ++i) {
        const int fd = backend_->createUdp();
        if (fd < 0) break;
        if (!backend_->bindV4(fd, /*addr_be=*/0, /*port=*/0)) {  // kernel-assigned ephemeral
            backend_->closeFd(fd);
            break;
        }
        udp_receive_ports_.push_back(fd);
        ++actual;
    }
    // §4.6.5.5 UI_01 report corruption: the ports were bound, but a buggy DUT miscounts
    // them in the CreateUdpReceivePorts Confirmation (an off-by-one over-report). Armed
    // lwIP-only via OpSetAppFlavor; udp_user_interface_01_neg passes only when the
    // reported count differs from the conformant 10.
    if (app_fault_flavor_.load(std::memory_order_relaxed) == kAppFaultMiscountPorts) {
        return static_cast<std::uint8_t>(actual + kReportPortOverCount);
    }
    return actual;
}

std::optional<UpperTesterServer::ReceiveRecord>
UpperTesterServer::lookupReceipt(std::uint16_t listen_port, std::uint32_t expected_dst_ip_be) {
    std::lock_guard<std::mutex> lk(log_mu_);
    if (!last_receipt_.populated || last_receipt_.dst_port != listen_port) {
        return std::nullopt;
    }
    // expected_dst_ip_be == 0 matches any destination ("was anything received?").
    if (expected_dst_ip_be != 0 && last_receipt_.dst_ip != expected_dst_ip_be) {
        return std::nullopt;
    }
    return last_receipt_;
}

}  // namespace tc8::ut
