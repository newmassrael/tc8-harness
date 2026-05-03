#pragma once

#include <cstdint>
#include <memory>

#include <v1/org/tc8/ets2/EnhancedTestability2StubDefault.hpp>

namespace tc8::dut {

// SERVICE-ID-2 stub for §5.1.5 multi-service axis (RPC_01/_02/_13).
// Single UDP echo method + one broadcast event — minimum surface to
// drive tester-side Method Request observations and Notification flow.
class EtsImpl2 : public v1::org::tc8::ets2::EnhancedTestability2StubDefault {
public:
    EtsImpl2() = default;

    void echoUINT8(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint8_t _value,
        echoUINT8Reply_t _reply) override;
};

}  // namespace tc8::dut
