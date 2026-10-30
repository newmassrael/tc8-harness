#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "sce_integration/dut_control_compose.h"
#include "sce_integration/dut_control_extension.h"

// The composition rules of a backend and the DUT-control extensions registered for
// it (dut_control_compose.h): an extension ADDS a seam, claims exactly what it
// answers, and the handle returns the extension's answer as given.

namespace tc8::sce {
namespace {

class FakePrimitive final : public IServicePrimitiveControl {
public:
    DutPrimitiveReply call(std::uint8_t, std::uint8_t, const std::vector<std::uint8_t> &) override {
        return {};
    }
};

class FakeArp final : public IArpControl {
public:
    int ageCacheBySeconds(std::uint16_t) override { return 0; }
    int addStaticEntry(std::uint32_t, const std::array<std::uint8_t, 6> &) override { return 0; }
    int removeStaticEntry(std::uint32_t) override { return 0; }
};

// A backend with a primitive call (what extensions are built over) and, optionally,
// an ARP seam of its own.
class FakeBackend final : public IDutControl {
public:
    explicit FakeBackend(bool has_primitive = true, bool has_arp = false)
        : has_primitive_(has_primitive), has_arp_(has_arp) {}

    bool probe() override { return true; }
    bool startTest() override { return true; }
    bool endTest() override { return true; }
    const char *backendName() const override { return "fake-backend"; }
    std::uint16_t controlPort() const override { return 4242; }
    DutCapabilities capabilities() const override {
        return (has_primitive_ ? kCapServicePrimitive : 0U) | (has_arp_ ? kCapArpConditioning : 0U);
    }
    IServicePrimitiveControl *servicePrimitiveControl() override {
        return has_primitive_ ? &primitive_ : nullptr;
    }
    IArpControl *arpControl() override { return has_arp_ ? &arp_ : nullptr; }

private:
    bool has_primitive_;
    bool has_arp_;
    FakePrimitive primitive_;
    FakeArp arp_;
};

// An extension answering the TCP state query with a fixed state.
class FixedStateQuery final : public ITcpStateQuery {
public:
    explicit FixedStateQuery(DutTcpState s) : state_(s) {}
    std::optional<DutTcpState> queryState(DutSocket) override { return state_; }

private:
    DutTcpState state_;
};

class StateExtension : public DutControlExtension {
public:
    StateExtension(std::string name, DutTcpState answer, DutCapabilities claimed)
        : name_(std::move(name)), query_(answer), claimed_(claimed) {}
    std::string_view name() const override { return name_; }
    DutCapabilities capabilities() const override { return claimed_; }
    ITcpStateQuery *tcpStateQuery() override { return &query_; }

private:
    std::string name_;
    FixedStateQuery query_;
    DutCapabilities claimed_;
};

class ArpExtension final : public DutControlExtension {
public:
    std::string_view name() const override { return "arp-ext"; }
    DutCapabilities capabilities() const override { return kCapArpConditioning; }
    IArpControl *arpControl() override { return &arp_; }

private:
    FakeArp arp_;
};

DutControlExtensionFactory stateExt(std::string name, DutTcpState answer,
                                    DutCapabilities claimed = kCapTcpStateQuery) {
    return [=](IServicePrimitiveControl &) {
        return std::make_unique<StateExtension>(name, answer, claimed);
    };
}

std::unique_ptr<IDutControl> compose(std::unique_ptr<IDutControl> backend,
                                     std::vector<DutControlExtensionFactory> factories) {
    return std::make_unique<ExtendedDutControl>(std::move(backend), factories);
}

TEST(DutControlExtension, NoRegistrationLeavesTheBackendAsItIs) {
    auto backend = std::make_unique<FakeBackend>();
    IDutControl *raw = backend.get();
    const auto out = composeDutControlExtensions(std::move(backend), DutControlBackend::kTestability, {});
    EXPECT_EQ(out.get(), raw);
}

TEST(DutControlExtension, ARegistrationForAnotherBackendIsNotApplied) {
    auto backend = std::make_unique<FakeBackend>();
    IDutControl *raw = backend.get();
    std::vector<DutControlExtensionRegistration> regs;
    regs.push_back({DutControlBackend::kOpcode, stateExt("x", DutTcpState::kEstablished)});
    const auto out = composeDutControlExtensions(std::move(backend), DutControlBackend::kTestability, regs);
    EXPECT_EQ(out.get(), raw);
}

TEST(DutControlExtension, AnExtensionAddsASeamAndItsBit) {
    auto handle = compose(std::make_unique<FakeBackend>(),
                          {stateExt("ecu-x", DutTcpState::kEstablished)});
    ASSERT_NE(handle->tcpStateQuery(), nullptr);
    EXPECT_NE(handle->capabilities() & kCapTcpStateQuery, 0U);
    EXPECT_NE(handle->staticCapabilities() & kCapTcpStateQuery, 0U);
    // The backend's own seam and bits are untouched.
    EXPECT_NE(handle->capabilities() & kCapServicePrimitive, 0U);
    EXPECT_NE(handle->servicePrimitiveControl(), nullptr);
    EXPECT_STREQ(handle->backendName(), "fake-backend");
    EXPECT_EQ(handle->controlPort(), 4242U);
    EXPECT_EQ(handle->tcpInfoProbe(), nullptr) << "a seam nobody offers stays absent";
}

TEST(DutControlExtension, TheRunNamesTheExtensionBehindEachSeam) {
    auto handle = compose(std::make_unique<FakeBackend>(),
                          {stateExt("ecu-x", DutTcpState::kEstablished)});
    EXPECT_NE(handle->seamProvenance().find("tcpStateQuery: extension 'ecu-x'"), std::string::npos);
    FakeBackend plain;
    EXPECT_TRUE(plain.seamProvenance().empty());
}

TEST(DutControlExtension, TheHandleReturnsTheExtensionsAnswerAsGiven) {
    // A claim does not make an answer right; the handle must not launder one. An
    // extension that claims the state query and reports CLOSED is read as CLOSED, so
    // a case that declares the bit and asserts establishment goes red on it.
    auto handle = compose(std::make_unique<FakeBackend>(), {stateExt("liar", DutTcpState::kClosed)});
    const auto state = handle->tcpStateQuery()->queryState(DutSocket{1});
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(*state, DutTcpState::kClosed);
    EXPECT_EQ(isEstablished(state), std::optional<bool>{false});
}

TEST(DutControlExtension, AnExtensionCannotReplaceABackendSeam) {
    EXPECT_THROW(compose(std::make_unique<FakeBackend>(true, /*has_arp=*/true),
                         {[](IServicePrimitiveControl &) { return std::make_unique<ArpExtension>(); }}),
                 DutControlExtensionError);
}

TEST(DutControlExtension, TwoExtensionsCannotOfferTheSameSeam) {
    EXPECT_THROW(compose(std::make_unique<FakeBackend>(),
                         {stateExt("a", DutTcpState::kEstablished),
                          stateExt("b", DutTcpState::kEstablished)}),
                 DutControlExtensionError);
}

TEST(DutControlExtension, AClaimWiderThanTheAnswerIsRefused) {
    // Claims the TCP_INFO probe as well as the state query it provides: cases
    // declaring kCapTcpInfoProbe would run into a nullptr instead of skipping.
    EXPECT_THROW(compose(std::make_unique<FakeBackend>(),
                         {stateExt("wide", DutTcpState::kEstablished,
                                   kCapTcpStateQuery | kCapTcpInfoProbe)}),
                 DutControlExtensionError);
}

TEST(DutControlExtension, AClaimNarrowerThanTheAnswerIsRefused) {
    EXPECT_THROW(compose(std::make_unique<FakeBackend>(),
                         {stateExt("narrow", DutTcpState::kEstablished, 0U)}),
                 DutControlExtensionError);
}

TEST(DutControlExtension, ABackendWithoutAPrimitiveCallCannotHostOne) {
    EXPECT_THROW(compose(std::make_unique<FakeBackend>(/*has_primitive=*/false),
                         {stateExt("x", DutTcpState::kEstablished)}),
                 DutControlExtensionError);
}

TEST(DutControlExtension, ARefusalNamesTheExtensionAndTheSeam) {
    try {
        compose(std::make_unique<FakeBackend>(),
                {stateExt("a", DutTcpState::kEstablished), stateExt("b", DutTcpState::kEstablished)});
        FAIL() << "expected a startup error";
    } catch (const DutControlExtensionError &e) {
        const std::string what = e.what();
        EXPECT_NE(what.find("'a'"), std::string::npos) << what;
        EXPECT_NE(what.find("'b'"), std::string::npos) << what;
        EXPECT_NE(what.find("tcpStateQuery"), std::string::npos) << what;
    }
}

TEST(DutControlExtension, TheRegistryKeepsWhatWasRegisteredForABackend) {
    DutControlExtensionRegistry registry;
    registry.add(DutControlBackend::kTestability, stateExt("x", DutTcpState::kEstablished));
    ASSERT_EQ(registry.all().size(), 1U);
    EXPECT_EQ(registry.all()[0].backend, DutControlBackend::kTestability);
}

}  // namespace
}  // namespace tc8::sce
