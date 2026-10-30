#include "demo_dut_extension.h"

#include <optional>
#include <vector>

#include "sce_integration/dut_call_intent.h"

namespace tc8::sce::demo {

std::optional<DutTcpState> mapDemoState(std::uint8_t value) {
    switch (value) {
        case kDemoStateClosed: return DutTcpState::kClosed;
        case kDemoStateListen: return DutTcpState::kListen;
        case kDemoStateSynSent: return DutTcpState::kSynSent;
        case kDemoStateSynReceived: return DutTcpState::kSynReceived;
        case kDemoStateEstablished: return DutTcpState::kEstablished;
        case kDemoStateFinWait1: return DutTcpState::kFinWait1;
        case kDemoStateFinWait2: return DutTcpState::kFinWait2;
        case kDemoStateCloseWait: return DutTcpState::kCloseWait;
        case kDemoStateClosing: return DutTcpState::kClosing;
        case kDemoStateLastAck: return DutTcpState::kLastAck;
        case kDemoStateTimeWait: return DutTcpState::kTimeWait;
        default: return std::nullopt;
    }
}

namespace {

class DemoStateQuery final : public ITcpStateQuery {
public:
    DemoStateQuery(IServicePrimitiveControl &transport, bool mislabel_established)
        : transport_(transport), mislabel_established_(mislabel_established) {}

    std::optional<DutTcpState> queryState(DutSocket sock) override {
        const std::vector<std::uint8_t> request{static_cast<std::uint8_t>(sock.id >> 8),
                                                static_cast<std::uint8_t>(sock.id & 0xFF)};
        // A state read is an observation whatever the DUT answers, so it is a graded call:
        // a refusal is the DUT's answer and is not recorded as a stimulus that did not take.
        const DutCallIntentScope graded(DutCallIntent::kGraded);
        const DutPrimitiveReply reply = transport_.call(kDemoGid, kDemoPidQueryState, request);
        if (!reply.succeeded() || reply.data.empty()) {
            return std::nullopt;  // no usable answer: the case stays inconclusive
        }
        auto state = mapDemoState(reply.data[0]);
        if (mislabel_established_ && state == DutTcpState::kEstablished) {
            return DutTcpState::kClosed;
        }
        return state;
    }

private:
    IServicePrimitiveControl &transport_;
    bool mislabel_established_;
};

class DemoDutExtension final : public DutControlExtension {
public:
    DemoDutExtension(IServicePrimitiveControl &transport, bool mislabel_established)
        : query_(transport, mislabel_established) {}

    std::string_view name() const override { return "demo-dut-extension"; }
    // The bit for the one seam this provides, and no other.
    DutCapabilities capabilities() const override { return kCapTcpStateQuery; }
    ITcpStateQuery *tcpStateQuery() override { return &query_; }

private:
    DemoStateQuery query_;
};

}  // namespace

std::unique_ptr<DutControlExtension> makeDemoDutExtension(IServicePrimitiveControl &transport,
                                                          bool mislabel_established) {
    return std::make_unique<DemoDutExtension>(transport, mislabel_established);
}

}  // namespace tc8::sce::demo
