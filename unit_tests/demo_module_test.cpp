#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/autosar/nm.h"
#include "demo_module.h"
#include "tc8/testability_protocol.h"
#include "tc8/testability/middleware.h"

namespace tc8::demo {
namespace {

// In-memory SocketBackend: records datagrams the module sends; every other op is
// a benign stub (the demo only opens/binds a UDP socket and sends).
class FakeBackend : public tc8::net::SocketBackend {
public:
    struct Sent {
        std::vector<std::uint8_t> bytes;
        tc8::net::Endpoint dst;
    };
    std::vector<Sent> sent;
    std::deque<std::vector<std::uint8_t>> inbound;  // queued datagrams recvFromV4 returns
    bool createUdpFails = false;

    int createUdp() override { return createUdpFails ? -1 : 1; }
    int createTcp() override { return 2; }
    void setReuseAddr(int) override {}
    void setBroadcast(int) override {}
    void setRecvTimeoutMs(int, int) override {}
    bool bindV4(int, std::uint32_t, std::uint16_t) override { return true; }
    int recvFromV4(int, void* buf, std::size_t len, tc8::net::Endpoint&) override {
        if (inbound.empty()) {
            return -1;  // nothing queued
        }
        const std::vector<std::uint8_t> dg = std::move(inbound.front());
        inbound.pop_front();
        const std::size_t take = dg.size() < len ? dg.size() : len;
        std::memcpy(buf, dg.data(), take);
        return static_cast<int>(dg.size());  // true datagram length (MSG_TRUNC semantics)
    }
    int sendToV4(int, const void* buf, std::size_t len, const tc8::net::Endpoint& dst) override {
        const auto* p = static_cast<const std::uint8_t*>(buf);
        sent.push_back({std::vector<std::uint8_t>(p, p + len), dst});
        return static_cast<int>(len);
    }
    bool joinMulticast(int, std::uint32_t, std::uint32_t) override { return true; }
    bool leaveMulticast(int, std::uint32_t, std::uint32_t) override { return true; }
    bool flushDynamicArp(const std::string&) override { return true; }
    bool addStaticNeighbor(const std::string&, std::uint32_t, const std::uint8_t*) override {
        return true;
    }
    bool removeNeighbor(const std::string&, std::uint32_t) override { return true; }
    bool setNeighborReachableMs(const std::string&, int) override { return true; }
    int recv(int, void*, std::size_t) override { return -1; }
    int send(int, const void*, std::size_t) override { return -1; }
    bool connectBoundedV4(int, const tc8::net::Endpoint&, int) override { return false; }
    bool listen(int, int) override { return false; }
    int accept(int, tc8::net::Endpoint&) override { return -1; }
    bool shutdown(int, int) override { return true; }
    void setNonBlocking(int, bool) override {}
    int waitReadable(int, int) override { return 0; }
    void closeFd(int) override {}
    void closeWithAbort(int) override {}
};

// Mock MiddlewareContext: timers are stored, not real; fire(period) invokes every
// timer armed with that period (the demo uses distinct periods per timer, so this
// targets one without depending on arm order). emitEvent is recorded.
class FakeContext : public tc8::testability::MiddlewareContext {
public:
    struct Event {
        std::uint8_t gid;
        std::uint8_t pid;
        std::vector<std::uint8_t> dat;
    };
    FakeBackend be;
    std::vector<Event> events;

    tc8::net::SocketBackend& backend() override { return be; }
    tc8::testability::TimerId scheduleEvery(std::chrono::milliseconds period,
                                            std::function<void()> fn) override {
        return store(period, std::move(fn));
    }
    tc8::testability::TimerId scheduleOnce(std::chrono::milliseconds period,
                                           std::function<void()> fn) override {
        return store(period, std::move(fn));
    }
    void cancel(tc8::testability::TimerId id) override { timers_.erase(id); }
    tc8::testability::WatchId watchReadable(int fd, std::function<void()> fn) override {
        const auto id = static_cast<tc8::testability::WatchId>(next_++);
        watches_[id] = {fd, std::move(fn)};
        return id;
    }
    void unwatch(tc8::testability::WatchId id) override { watches_.erase(id); }
    void emitEvent(std::uint8_t gid, std::uint8_t pid,
                   const std::vector<std::uint8_t>& dat) override {
        events.push_back({gid, pid, dat});
    }

    void fire(std::chrono::milliseconds period) {
        for (auto& kv : timers_) {
            if (kv.second.first == period) {
                kv.second.second();
            }
        }
    }

    // Stand in for the reactor: invoke every watch handler registered on `fd`
    // (the test queues a datagram in `be.inbound` first, mirroring poll readiness).
    void deliverReadable(int fd) {
        for (auto& kv : watches_) {
            if (kv.second.first == fd) {
                kv.second.second();
            }
        }
    }

private:
    tc8::testability::TimerId store(std::chrono::milliseconds period, std::function<void()> fn) {
        const auto id = static_cast<tc8::testability::TimerId>(next_++);
        timers_[id] = {period, std::move(fn)};
        return id;
    }
    std::uint64_t next_ = 1;
    std::map<tc8::testability::TimerId, std::pair<std::chrono::milliseconds, std::function<void()>>>
        timers_;
    std::map<tc8::testability::WatchId, std::pair<int, std::function<void()>>> watches_;
};

using ms = std::chrono::milliseconds;

tc8::testability::Header reqFor(std::uint8_t pid) {
    tc8::testability::Header h;
    h.method_id = tc8::testability::methodId(DemoModule::kGroup, pid);
    return h;
}

std::uint8_t callPrimitive(DemoModule& m, std::uint8_t pid, const std::vector<std::uint8_t>& dat,
                           std::vector<std::uint8_t>& resp) {
    std::uint8_t rid = tc8::testability::kRidEInv;
    m.onPrimitive(reqFor(pid), dat.data(), dat.size(), tc8::net::Endpoint{}, rid, resp);
    return rid;
}

TEST(DemoModule, OwnsOemReservedGroup) {
    DemoModule m;
    EXPECT_EQ(m.groups(), std::vector<std::uint8_t>{DemoModule::kGroup});
}

// A network request drives the NM machine out of Bus Sleep and announces it.
TEST(DemoModule, RequestNetworkTransitionsAndEmits) {
    DemoModule m;
    FakeContext ctx;
    m.onStart(ctx);
    std::vector<std::uint8_t> resp;
    EXPECT_EQ(callPrimitive(m, DemoModule::kPidRequestNetwork, {}, resp),
              tc8::testability::kRidEOk);
    // Repeat Message entry emitted a state-change EVENT to the OEM group.
    ASSERT_FALSE(ctx.events.empty());
    EXPECT_EQ(ctx.events.front().gid, DemoModule::kGroup);
    EXPECT_EQ(ctx.events.front().pid, DemoModule::kPidStateEvent);
    EXPECT_EQ(ctx.events.front().dat.front(),
              static_cast<std::uint8_t>(tc8::nm::State::kRepeatMessage));
    m.onStop();
}

// GetNmState reports the live state byte.
TEST(DemoModule, GetNmStateReflectsMachine) {
    DemoModule m;
    FakeContext ctx;
    m.onStart(ctx);
    std::vector<std::uint8_t> resp;
    callPrimitive(m, DemoModule::kPidRequestNetwork, {}, resp);
    resp.clear();
    EXPECT_EQ(callPrimitive(m, DemoModule::kPidGetNmState, {}, resp), tc8::testability::kRidEOk);
    ASSERT_EQ(resp.size(), 1u);
    EXPECT_EQ(resp[0], static_cast<std::uint8_t>(tc8::nm::State::kRepeatMessage));
    m.onStop();
}

// The cyclic COM timer packs a signal, E2E-protects it, and sends 8 bytes.
TEST(DemoModule, CyclicTxSendsProtectedSignalPdu) {
    DemoModule m;
    FakeContext ctx;
    m.onStart(ctx);
    std::vector<std::uint8_t> resp;
    callPrimitive(m, DemoModule::kPidSetSignal, {0x34, 0x12}, resp);
    ctx.be.sent.clear();
    ctx.fire(ms{100});  // the COM cycle
    ASSERT_EQ(ctx.be.sent.size(), 1u);
    EXPECT_EQ(ctx.be.sent[0].bytes.size(), 8u);
    EXPECT_EQ(ctx.be.sent[0].dst.port, 30490);
    // The E2E counter (byte 2 at offset 0) advanced to 1 on the first protect.
    EXPECT_EQ(ctx.be.sent[0].bytes[2], 0x01);
    m.onStop();
}

// Ticking the NM timer with the network requested reaches Normal Operation.
TEST(DemoModule, NmTickReachesNormalOperation) {
    DemoModule m;
    FakeContext ctx;
    m.onStart(ctx);
    std::vector<std::uint8_t> resp;
    callPrimitive(m, DemoModule::kPidRequestNetwork, {}, resp);
    ctx.fire(ms{500});  // repeat_message (1000ms) not yet elapsed -> still Repeat Message
    ctx.fire(ms{500});  // total 1000ms -> Normal Operation
    callPrimitive(m, DemoModule::kPidGetNmState, {}, resp = {});
    EXPECT_EQ(resp[0], static_cast<std::uint8_t>(tc8::nm::State::kNormalOperation));
    m.onStop();
}

// Authenticate returns a 16-byte AES-CMAC.
TEST(DemoModule, AuthenticateReturnsCmac) {
    DemoModule m;
    FakeContext ctx;
    m.onStart(ctx);
    std::vector<std::uint8_t> resp;
    EXPECT_EQ(callPrimitive(m, DemoModule::kPidAuthenticate, {0x01, 0x02, 0x03}, resp),
              tc8::testability::kRidEOk);
    EXPECT_EQ(resp.size(), 16u);
    m.onStop();
}

TEST(DemoModule, UnknownPidNotFound) {
    DemoModule m;
    FakeContext ctx;
    m.onStart(ctx);
    std::vector<std::uint8_t> resp;
    EXPECT_EQ(callPrimitive(m, 0x00, {}, resp), tc8::testability::kRidENtf);
    m.onStop();
}

// If the data-plane socket cannot be set up, the module degrades cleanly: no
// periodic transmit is armed (nothing is sent), but control primitives still work.
TEST(DemoModule, DegradesWhenSocketSetupFails) {
    DemoModule m;
    FakeContext ctx;
    ctx.be.createUdpFails = true;
    m.onStart(ctx);
    ctx.fire(ms{100});
    ctx.fire(ms{500});
    EXPECT_TRUE(ctx.be.sent.empty());
    std::vector<std::uint8_t> resp;
    EXPECT_EQ(callPrimitive(m, DemoModule::kPidGetNmState, {}, resp), tc8::testability::kRidEOk);
    m.onStop();
}

// Inbound PDU path (the rx reactor's reason to exist): a datagram delivered to the
// watched data socket is unpacked by the COM engine, recorded for GetLastSignal,
// and surfaced as an rx EVENT — all on the executor, no private receive thread.
TEST(DemoModule, InboundPduUnpackedRecordedAndEmitted) {
    DemoModule m;
    FakeContext ctx;
    m.onStart(ctx);

    // Before any inbound PDU, GetLastSignal is unambiguously "not found".
    std::vector<std::uint8_t> resp;
    EXPECT_EQ(callPrimitive(m, DemoModule::kPidGetLastSignal, {}, resp),
              tc8::testability::kRidENtf);

    // A COM I-PDU carrying the speed signal (start_bit 24, 16 bits, little-endian)
    // = 0x1234 -> byte 3 = 0x34 (LSB), byte 4 = 0x12. Queue it and fire the watch.
    std::vector<std::uint8_t> pdu(8, 0x00);
    pdu[3] = 0x34;
    pdu[4] = 0x12;
    ctx.be.inbound.push_back(pdu);
    ctx.deliverReadable(/*fd=*/1);  // FakeBackend::createUdp() returned 1

    // The rx EVENT carries the unpacked value (2 bytes, little-endian).
    ASSERT_FALSE(ctx.events.empty());
    EXPECT_EQ(ctx.events.back().gid, DemoModule::kGroup);
    EXPECT_EQ(ctx.events.back().pid, DemoModule::kPidSignalRxEvent);
    EXPECT_EQ(ctx.events.back().dat, (std::vector<std::uint8_t>{0x34, 0x12}));

    // GetLastSignal now reflects the consumed signal.
    resp.clear();
    EXPECT_EQ(callPrimitive(m, DemoModule::kPidGetLastSignal, {}, resp),
              tc8::testability::kRidEOk);
    EXPECT_EQ(resp, (std::vector<std::uint8_t>{0x34, 0x12}));
    m.onStop();
}

// SOME/IP-TP composition: a tx primitive segments a payload and sends each segment;
// looping those segments back through the rx reactor reassembles the original message
// and emits its length as an EVENT (the hardest engine to wire, end to end).
TEST(DemoModule, TpSegmentsAndReassemblesThroughModule) {
    DemoModule m;
    FakeContext ctx;
    m.onStart(ctx);

    std::vector<std::uint8_t> payload(40);  // > kTpMaxSegment (16) -> multiple segments
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>(i);
    }
    std::vector<std::uint8_t> resp;
    EXPECT_EQ(callPrimitive(m, DemoModule::kPidSendLarge, payload, resp),
              tc8::testability::kRidEOk);
    ASSERT_GE(ctx.be.sent.size(), 2u);  // genuinely segmented

    // Loop every emitted segment back in as inbound and drive the rx reactor once per
    // datagram (level-triggered: the handler drains exactly one each time).
    for (const auto& s : ctx.be.sent) {
        ctx.be.inbound.push_back(s.bytes);
    }
    const std::size_t segs = ctx.be.inbound.size();
    for (std::size_t i = 0; i < segs; ++i) {
        ctx.deliverReadable(/*fd=*/1);
    }

    bool reassembled = false;
    for (const auto& e : ctx.events) {
        if (e.pid == DemoModule::kPidTpRxEvent) {
            EXPECT_EQ(e.dat, (std::vector<std::uint8_t>{40, 0}));  // original length, LE
            reassembled = true;
        }
    }
    EXPECT_TRUE(reassembled);

    resp.clear();
    EXPECT_EQ(callPrimitive(m, DemoModule::kPidGetLastTpLen, {}, resp),
              tc8::testability::kRidEOk);
    EXPECT_EQ(resp, (std::vector<std::uint8_t>{40, 0}));
    m.onStop();
}

// Partial-Networking relevance: a PDU whose PN range shares the ECU's cluster bit is
// relevant; one that does not is not.
TEST(DemoModule, PnRelevanceFiltersByClusterMask) {
    DemoModule m;
    FakeContext ctx;
    m.onStart(ctx);

    std::vector<std::uint8_t> resp;
    std::vector<std::uint8_t> relevant(8, 0x00);
    relevant[3] = 0x01;  // PN range (offset 3) shares the fabricated mask bit 0x01
    EXPECT_EQ(callPrimitive(m, DemoModule::kPidPnRelevant, relevant, resp),
              tc8::testability::kRidEOk);
    ASSERT_EQ(resp.size(), 1u);
    EXPECT_EQ(resp[0], 1);

    resp.clear();
    std::vector<std::uint8_t> other(8, 0x00);
    other[3] = 0x02;  // a different cluster bit -> not relevant to this ECU
    callPrimitive(m, DemoModule::kPidPnRelevant, other, resp);
    ASSERT_EQ(resp.size(), 1u);
    EXPECT_EQ(resp[0], 0);
    m.onStop();
}

}  // namespace
}  // namespace tc8::demo
