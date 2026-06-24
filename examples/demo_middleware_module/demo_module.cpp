#include "demo_module.h"

#include <array>

#include "autosar/aes_cmac.h"
#include "tc8/testability_protocol.h"

namespace tc8::demo {
namespace {

using namespace std::chrono_literals;

// Fabricated configuration — shapes only, no OEM values.
constexpr std::uint8_t  kNodeId = 0x10;
constexpr std::uint32_t kComPduId = 1;
constexpr std::uint32_t kSpeedSignalId = 10;
constexpr std::chrono::milliseconds kNmTick{500};
constexpr std::chrono::milliseconds kComCycle{100};

// Synthetic loopback destination for the data-plane PDUs (127.0.0.1:30490, NBO).
const tc8::net::Endpoint kPeer{0x0100007FU, 30490};

tc8::nm::StateMachine makeNm() {
    return tc8::nm::StateMachine(
        tc8::nm::Timing{kNmTick, 2000ms, 1000ms, 1500ms},
        tc8::nm::PduLayout{8, 0, 1, 2, 5}, kNodeId);
}

tc8::com::SignalEngine makeCom() {
    // Signal sits after the 3-byte E2E header (CRC[0..1] + counter[2]) so protect
    // does not overwrite it; the E2E CRC then covers the signal bytes.
    return tc8::com::SignalEngine({tc8::com::PduDef{
        kComPduId, 8, kComCycle, 0ms, tc8::com::SendType::kCyclic,
        {tc8::com::SignalDef{kSpeedSignalId, 24, 16, tc8::com::Endianness::kLittle}}}});
}

tc8::e2e::Profile05Protector makeE2e() {
    return tc8::e2e::Profile05Protector(tc8::e2e::Profile05Config{0x0BAD, 0, 1});
}

}  // namespace

DemoModule::DemoModule() : nm_(makeNm()), com_(makeCom()), e2e_(makeE2e()) {}

std::vector<std::uint8_t> DemoModule::groups() const { return {kGroup}; }

void DemoModule::onStart(tc8::testability::MiddlewareContext& ctx) {
    ctx_ = &ctx;
    sock_ = ctx.backend().createUdp();
    ctx.backend().bindV4(sock_, 0, 0);

    // NM transmits through the data-plane socket and announces each transition.
    nm_.onTransmit = [this](const std::vector<std::uint8_t>& pdu) {
        if (ctx_ != nullptr) {
            ctx_->backend().sendToV4(sock_, pdu.data(), pdu.size(), kPeer);
        }
    };
    nm_.onTransition = [this](tc8::nm::State, tc8::nm::State to) {
        if (ctx_ != nullptr) {
            ctx_->emitEvent(kGroup, kPidStateEvent, {static_cast<std::uint8_t>(to)});
        }
    };

    nm_timer_ = ctx.scheduleEvery(kNmTick, [this] { nm_.mainFunction(kNmTick); });
    com_timer_ = ctx.scheduleEvery(kComCycle, [this] { transmitSignalPdu(); });
}

void DemoModule::onStop() {
    if (ctx_ != nullptr) {
        ctx_->cancel(nm_timer_);
        ctx_->cancel(com_timer_);
        if (sock_ >= 0) {
            ctx_->backend().closeFd(sock_);
        }
    }
    ctx_ = nullptr;
}

void DemoModule::transmitSignalPdu() {
    std::vector<std::uint8_t> pdu = com_.packPdu(kComPduId);
    e2e_.protect(pdu.data(), pdu.size());  // CRC-16 + counter over the signal PDU
    if (ctx_ != nullptr) {
        ctx_->backend().sendToV4(sock_, pdu.data(), pdu.size(), kPeer);
    }
}

void DemoModule::onPrimitive(const tc8::testability::Header& req, const std::uint8_t* dat,
                             std::size_t dat_len, const tc8::net::Endpoint& /*peer*/,
                             std::uint8_t& rid_out, std::vector<std::uint8_t>& resp_dat) {
    switch (tc8::testability::pidOf(req.method_id)) {
        case kPidRequestNetwork:
            nm_.requestNetwork();
            rid_out = tc8::testability::kRidEOk;
            return;
        case kPidReleaseNetwork:
            nm_.releaseNetwork();
            rid_out = tc8::testability::kRidEOk;
            return;
        case kPidGetNmState:
            resp_dat.push_back(static_cast<std::uint8_t>(nm_.state()));
            rid_out = tc8::testability::kRidEOk;
            return;
        case kPidSetSignal: {
            std::uint64_t value = 0;
            for (std::size_t i = 0; i < dat_len && i < 8; ++i) {
                value |= static_cast<std::uint64_t>(dat[i]) << (8 * i);
            }
            com_.setSignal(kSpeedSignalId, value);
            rid_out = tc8::testability::kRidEOk;
            return;
        }
        case kPidAuthenticate: {
            const std::array<std::uint8_t, 16> key{};  // fabricated zero key
            const std::array<std::uint8_t, 16> mac =
                tc8::crypto::aesCmac(key.data(), key.size(), dat, dat_len);
            resp_dat.assign(mac.begin(), mac.end());
            rid_out = tc8::testability::kRidEOk;
            return;
        }
        default:
            rid_out = tc8::testability::kRidENtf;
            return;
    }
}

void DemoModule::onEndTest() {
    nm_.releaseNetwork();  // return toward the inactive (sleep) state between tests
}

}  // namespace tc8::demo
