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

// Synthetic loopback destination for the data-plane PDUs. addr_be is network byte
// order: 0x0100007F == htonl(127.0.0.1) on a little-endian host (the build targets
// are x86/aarch64, both LE). Port 30490 is the public SOME/IP-SD default, not OEM.
const tc8::net::Endpoint kPeer{0x0100007FU, 30490};

// Max inbound datagram the rx handler reads in one go (an I-PDU is <= 8 bytes
// here; the buffer is generously sized for any fabricated frame).
constexpr std::size_t kRxBufLen = 256;

tc8::nm::StateMachine makeNm() {
    return tc8::nm::StateMachine(
        tc8::nm::Timing{kNmTick, 2000ms, 1000ms, 1500ms},
        tc8::nm::PduLayout{8, 0, 1, 2, 5}, kNodeId);
}

tc8::com::SignalEngine makeCom() {
    // Signal sits after the 3-byte E2E header (CRC[0..1] + counter[2]) so protect
    // does not overwrite it; the E2E CRC then covers the signal bytes.
    return tc8::com::SignalEngine({tc8::com::PduDef{
        kComPduId, 8,
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
    // Do not ignore the socket setup: a failed createUdp/bindV4 (e.g. the port is
    // taken on lwIP) leaves no data plane, so we skip arming the periodic tx and
    // the rx watch — control primitives are still answered. sock_ < 0 also
    // disables the tx guards. Bind a known port so a peer can address inbound PDUs.
    const bool socket_ready = sock_ >= 0 && ctx.backend().bindV4(sock_, 0, kDataPort);

    nm_.onTransmit = [this](const std::vector<std::uint8_t>& pdu) {
        if (ctx_ != nullptr && sock_ >= 0) {
            ctx_->backend().sendToV4(sock_, pdu.data(), pdu.size(), kPeer);
        }
    };
    nm_.onTransition = [this](tc8::nm::State, tc8::nm::State to) {
        if (ctx_ != nullptr) {
            ctx_->emitEvent(kGroup, kPidStateEvent, {static_cast<std::uint8_t>(to)});
        }
    };

    if (socket_ready) {
        nm_timer_ = ctx.scheduleEvery(kNmTick, [this] { nm_.mainFunction(kNmTick); });
        com_timer_ = ctx.scheduleEvery(kComCycle, [this] { transmitSignalPdu(); });
        // Inbound data plane: deliver each received datagram on the executor.
        rx_watch_ = ctx.watchReadable(sock_, [this] { onDataReadable(); });
    }
}

void DemoModule::onStop() {
    if (ctx_ != nullptr) {
        ctx_->cancel(nm_timer_);
        ctx_->cancel(com_timer_);
        ctx_->unwatch(rx_watch_);  // stop watching before the fd closes
        if (sock_ >= 0) {
            ctx_->backend().closeFd(sock_);
        }
    }
    ctx_ = nullptr;
}

void DemoModule::onDataReadable() {
    // Runs on the module executor (the reactor delivered readability on sock_).
    // Drain one datagram and let the COM engine unpack the inbound I-PDU; a real
    // module would E2E-check first and route by PDU id. The handler MUST consume
    // the datagram — the reactor is level-triggered.
    std::uint8_t buf[kRxBufLen];
    tc8::net::Endpoint src{};
    const int n = ctx_->backend().recvFromV4(sock_, buf, sizeof(buf), src);
    if (n <= 0) {
        return;
    }
    com_.unpackInto(kComPduId, buf, static_cast<std::size_t>(n));
    const std::optional<std::uint64_t> v = com_.lastReceived(kSpeedSignalId);
    if (!v.has_value()) {
        return;
    }
    last_rx_signal_ = v;
    // Surface the received value to the test system as an asynchronous EVENT
    // (2 bytes, little-endian) — the rx counterpart of the NM state EVENT.
    ctx_->emitEvent(kGroup, kPidSignalRxEvent,
                    {static_cast<std::uint8_t>(*v & 0xFF),
                     static_cast<std::uint8_t>((*v >> 8) & 0xFF)});
}

void DemoModule::transmitSignalPdu() {
    std::vector<std::uint8_t> pdu = com_.packPdu(kComPduId);
    e2e_.protect(pdu.data(), pdu.size());  // CRC-16 + counter over the signal PDU
    if (ctx_ != nullptr && sock_ >= 0) {
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
        case kPidGetLastSignal: {
            // The value the rx handler last unpacked (2 bytes LE). E_NTF until an
            // inbound PDU has been consumed, so a poll before any rx is unambiguous.
            if (!last_rx_signal_.has_value()) {
                rid_out = tc8::testability::kRidENtf;
                return;
            }
            const std::uint64_t v = *last_rx_signal_;
            resp_dat.push_back(static_cast<std::uint8_t>(v & 0xFF));
            resp_dat.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
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
