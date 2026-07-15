// In-process runtime test for the middleware rx reactor on the lwIP backend.
//
// The reactor logic is platform-agnostic and is runtime-tested on POSIX
// (unit_tests/testability_server_test.cpp). What is lwIP-specific and otherwise
// only build-verified is the lwIP IoMultiplexer: lwip_select-based poll() and the
// 127.0.0.1 socket-pair Waker (createWaker/signal/drain). This test exercises that
// path for real, entirely in-process over the loopback netif (LWIP_HAVE_LOOPIF,
// derived from LWIP_NETIF_LOOPBACK) — no tap, no netns, no root.
//
// It brings up only the lwIP stack (tcpip_init → auto-created 127/8 loopif),
// hosts a ProtocolServer with the lwIP backend and a probe MiddlewareModule that
// watchReadable()s a 127.0.0.1 data socket, then:
//   1. sends a datagram to that socket and confirms the reactor delivered it to
//      the module on its executor (poll readiness + watchReadable), and
//   2. sends a testability primitive to the control port and confirms the module
//      answered (the primitive is marshaled onto the executor — exercising the
//      Waker / liveness path end to end).
// Latency is deliberately NOT asserted (the 1 s liveness backstop would mask a
// broken waker only in timing, and a timing assert would be flaky); this is a
// functional proof that the lwIP reactor runs, consumes rx, and services
// marshaled work without hanging or crashing.

// C++ standard + tc8 headers FIRST, so every C++ declaration (the SocketBackend
// method names recv/send/poll/listen/..., and <functional> pulled in by the
// testability headers) is parsed before any lwIP header exists. lwIP's
// LWIP_COMPAT_SOCKETS layer defines bare-name function-like macros (bind/recv/
// send/poll/listen/...) that would otherwise clobber those names; including the
// lwIP headers last, and calling only the lwip_* forms below, sidesteps the
// collision without a fragile per-macro #undef list.
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

#include "lwip_socket_backend.h"
#include "tc8/testability_protocol.h"
#include "tc8/testability/middleware.h"
#include "tc8/testability/protocol_server.h"
#include "tc8/testability/reactor.h"

#include "lwip/init.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"

namespace tp = tc8::testability;

namespace {

constexpr std::uint16_t kControlPort = 30751;  // testability control endpoint
constexpr std::uint16_t kDataPort = 30752;     // the probe module's data plane
constexpr std::uint8_t kProbeGid = 0x7E;       // OEM-reserved (counts down from 0x7F)
constexpr std::uint8_t kProbePidGetCount = 0x01;
const std::uint32_t kLoopbackBe = PP_HTONL(IPADDR_LOOPBACK);  // 127.0.0.1, network order

int g_failures = 0;
void check(bool ok, const char *what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++g_failures;
    } else {
        std::fprintf(stderr, "ok: %s\n", what);
    }
}

// A minimal module: binds a 127.0.0.1 data socket, watches it, and counts inbound
// datagrams (on its executor). A GET_COUNT primitive returns the count — that
// request is marshaled onto the executor via the reactor's waker.
class RxProbe final : public tp::MiddlewareModule {
public:
    std::atomic<bool> rx_seen{false};

    std::vector<std::uint8_t> groups() const override { return {kProbeGid}; }
    void onStart(tp::MiddlewareContext &ctx) override {
        ctx_ = &ctx;
        sock_ = ctx.backend().createUdp();
        if (sock_ >= 0 && ctx.backend().bindV4(sock_, 0, kDataPort)) {
            watch_ = ctx.watchReadable(sock_, [this] { onRx(); });
        }
    }
    void onStop() override {
        if (ctx_ != nullptr) {
            ctx_->unwatch(watch_);
            if (sock_ >= 0) {
                ctx_->backend().closeFd(sock_);
            }
        }
        ctx_ = nullptr;
    }
    void onPrimitive(const tp::Header &req, const std::uint8_t *, std::size_t,
                     const tc8::net::Endpoint &, std::uint8_t &rid,
                     std::vector<std::uint8_t> &resp) override {
        if (tp::pidOf(req.method_id) == kProbePidGetCount) {
            resp.push_back(static_cast<std::uint8_t>(count_));  // executor-thread state
            rid = tp::kRidEOk;
        } else {
            rid = tp::kRidENtf;
        }
    }

private:
    void onRx() {
        std::uint8_t buf[64];
        tc8::net::Endpoint src{};
        const int n = ctx_->backend().recvFromV4(sock_, buf, sizeof(buf), src);
        if (n > 0) {
            ++count_;
            rx_seen.store(true);
        }
    }

    tp::MiddlewareContext *ctx_ = nullptr;
    int sock_ = -1;
    tp::WatchId watch_ = tp::kNoWatch;
    int count_ = 0;
};

void initSemSignal(void *sem) { sys_sem_signal(static_cast<sys_sem_t *>(sem)); }

// Bring up only the lwIP stack: tcpip_init creates the 127/8 loopif (no tap is
// added, so this needs no privileges or topology). UDP-only, so no TCP ISN seed.
void bringUpLoopbackOnlyStack() {
    sys_sem_t init_sem;
    if (sys_sem_new(&init_sem, 0) != ERR_OK) {
        std::fprintf(stderr, "FATAL: sys_sem_new failed\n");
        std::exit(3);
    }
    tcpip_init(initSemSignal, &init_sem);
    sys_sem_wait(&init_sem);
    sys_sem_free(&init_sem);
}

// A test-side lwIP UDP socket bound to an ephemeral 127.0.0.1 port, with a recv
// timeout so a missing response fails the test instead of hanging.
int makeLoopbackUdp(int recv_timeout_ms) {
    const int fd = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return -1;
    }
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = kLoopbackBe;
    a.sin_port = 0;
    if (lwip_bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0) {
        lwip_close(fd);
        return -1;
    }
    timeval tv{};
    tv.tv_sec = recv_timeout_ms / 1000;
    tv.tv_usec = (recv_timeout_ms % 1000) * 1000;
    lwip_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

void sendTo(int fd, std::uint16_t port, const std::uint8_t *data, std::size_t len) {
    sockaddr_in d{};
    d.sin_family = AF_INET;
    d.sin_addr.s_addr = kLoopbackBe;
    d.sin_port = lwip_htons(port);
    lwip_sendto(fd, data, len, 0, reinterpret_cast<sockaddr *>(&d), sizeof(d));
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    bringUpLoopbackOnlyStack();

    auto probe = std::make_unique<RxProbe>();
    RxProbe *probe_ptr = probe.get();
    tp::ProtocolServer server{std::make_unique<tc8::lwip_dut::LwipSocketBackend>()};
    server.registerModule(std::move(probe));
    check(server.start(kControlPort), "ProtocolServer.start on loopback");

    // 1) rx path: a datagram to the probe's data port must reach onRx via the
    //    reactor's poll readiness on a real lwIP socket.
    const int tx = makeLoopbackUdp(/*recv_timeout_ms=*/0);
    check(tx >= 0, "create test sender socket");
    const std::uint8_t payload[] = {0xC0, 0xDE};
    sendTo(tx, kDataPort, payload, sizeof(payload));

    bool rx = false;
    for (int i = 0; i < 200 && !rx; ++i) {  // up to ~2 s, bounded
        rx = probe_ptr->rx_seen.load();
        if (!rx) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    check(rx, "reactor delivered the inbound datagram to the module (watchReadable)");

    // 2) waker / marshaling path: a control primitive must be serviced by the
    //    module on its executor and answered back over the control socket.
    const int ctl = makeLoopbackUdp(/*recv_timeout_ms=*/2000);
    check(ctl >= 0, "create test control socket");
    tp::Header h;
    h.method_id = tp::methodId(kProbeGid, kProbePidGetCount);
    const std::vector<std::uint8_t> msg = tp::buildMessage(h);
    sendTo(ctl, kControlPort, msg.data(), msg.size());

    std::uint8_t rbuf[256];
    const ssize_t rn = lwip_recvfrom(ctl, rbuf, sizeof(rbuf), 0, nullptr, nullptr);
    check(rn >= static_cast<int>(tp::kHeaderSize), "control primitive got a response (waker path)");
    if (rn >= static_cast<int>(tp::kHeaderSize)) {
        const auto resp = tp::parseHeader(rbuf, static_cast<std::size_t>(rn));
        check(resp.has_value() && resp->rid == tp::kRidEOk, "primitive response is E_OK");
        const std::size_t dat_len = static_cast<std::size_t>(rn) - tp::kHeaderSize;
        check(dat_len == 1 && rbuf[tp::kHeaderSize] >= 1,
              "module reports >= 1 consumed datagram");
    }

    server.stop();  // joins server + module executor; must not hang
    check(true, "ProtocolServer.stop completed (no hang)");

    if (g_failures == 0) {
        std::fprintf(stderr, "lwip_reactor_test: PASS\n");
        return 0;
    }
    std::fprintf(stderr, "lwip_reactor_test: %d FAILURE(S)\n", g_failures);
    return 1;
}
