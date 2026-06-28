#include "ets2_impl.h"

namespace tc8::dut {

void Ets2Impl::echoUINT8(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint8_t _value,
    echoUINT8Reply_t _reply) {
    _reply(_value);
}

}  // namespace tc8::dut
