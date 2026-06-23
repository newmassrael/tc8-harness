#include "ets_impl.h"

#include <chrono>
#include <cstdlib>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "ets_fault.h"

namespace tc8::dut {

namespace {

// §5.1.6 SOMEIP_ETS_166/168 field-getter fault: when kEtsFaultFieldValueWrong is armed
// (via UT 0x1B OpSetEtsFlavor), the getter returns the stored value with every bit flipped
// — guaranteed != the value setField stored (x ^ 0xFF != x for all 8-bit x), so the
// positive's post-set-readback guard fails. The setter is left untouched (its echo stays
// correct), so the _neg mirrors the positive's get/set/get chain and only the final
// readback flips. None (the conformant path) returns the stored value verbatim.
inline std::uint8_t maybeFaultFieldValue(std::uint8_t stored) {
    return etsFaultFlavor() == ut::kEtsFaultFieldValueWrong
               ? static_cast<std::uint8_t>(stored ^ 0xFFU)
               : stored;
}


// §5.1.6 SOMEIP_ETS_097 vs _098..101 fork — env-gated so ETS_097 (Proxy
// path) and ETS_098..101 (raw-UDP path) can coexist without cross-test
// contamination. clientServiceActivate / clientServiceSubscribeEventgroup
// each consult this gate at dispatch time.
bool clientProxyModeEnabled() {
    const char* v = std::getenv("TC8_DUT_CLIENT_MODE");
    return v != nullptr && v[0] != '\0' && v[0] != '0';
}

// §5.1.6 SOMEIP_ETS_082 — selects the UDP-unreliable target event in
// ets3.fdepl (eventgroup 0x000B) instead of the default TCP-reliable
// event (eventgroup 0x000A used by ETS_081/_084/_097). Implies
// TC8_DUT_CLIENT_MODE=1; consulted only when proxy mode is active.
bool clientProxyModeUdpEnabled() {
    const char* v = std::getenv("TC8_DUT_CLIENT_MODE_UDP");
    return v != nullptr && v[0] != '\0' && v[0] != '0';
}

}  // namespace

void EtsImpl::checkByteOrder(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint8_t _summandUINT8,
    uint16_t _summandUINT16,
    checkByteOrderReply_t _reply) {
    const uint32_t sum = static_cast<uint32_t>(_summandUINT8) +
                         static_cast<uint32_t>(_summandUINT16);
    _reply(sum);
}

void EtsImpl::echoUINT8(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint8_t _value,
    echoUINT8Reply_t _reply) {
    _reply(_value);
}

void EtsImpl::echoCommonDatatypes(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    bool _arg1,
    uint8_t _arg2,
    uint16_t _arg3,
    uint32_t _arg4,
    int8_t _arg5,
    int16_t _arg6,
    int32_t _arg7,
    float _arg8,
    double _arg9,
    echoCommonDatatypesReply_t _reply) {
    _reply(_arg9, _arg8, _arg7, _arg6, _arg5, _arg4, _arg3, _arg2, _arg1);
}

void EtsImpl::echoUINT8RELIABLE(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint8_t _value,
    echoUINT8RELIABLEReply_t _reply) {
    _reply(_value);
}

void EtsImpl::echoINT8(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    int8_t _value,
    echoINT8Reply_t _reply) {
    _reply(_value);
}

void EtsImpl::getFieldA(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    getFieldAReply_t _reply) {
    _reply(maybeFaultFieldValue(fieldA_));
}

void EtsImpl::setFieldA(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint8_t _value,
    setFieldAReply_t _reply) {
    fieldA_ = _value;
    _reply(fieldA_);
}

// §5.1.6 SOMEIP_ETS_167 TestFieldUINT8Array.
void EtsImpl::getTestFieldUint8Array(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    getTestFieldUint8ArrayReply_t _reply) {
    _reply(testFieldUint8Array_);
}

void EtsImpl::setTestFieldUint8Array(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    std::vector<uint8_t> _data,
    setTestFieldUint8ArrayReply_t _reply) {
    testFieldUint8Array_ = std::move(_data);
    _reply(testFieldUint8Array_);
}

// §5.1.6 SOMEIP_ETS_168 TestFieldUINT8Reliable (TCP).
void EtsImpl::getTestFieldUint8Reliable(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    getTestFieldUint8ReliableReply_t _reply) {
    _reply(maybeFaultFieldValue(testFieldUint8Reliable_));
}

void EtsImpl::setTestFieldUint8Reliable(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint8_t _value,
    setTestFieldUint8ReliableReply_t _reply) {
    testFieldUint8Reliable_ = _value;
    _reply(testFieldUint8Reliable_);
}

void EtsImpl::echoFLOAT64(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    double _value,
    echoFLOAT64Reply_t _reply) {
    _reply(_value);
}

void EtsImpl::echoStaticUINT8Array(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    std::vector<uint8_t> _data,
    echoStaticUINT8ArrayReply_t _reply) {
    _reply(_data);
}

void EtsImpl::echoUINT8Array2Dim(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    std::vector<v1::org::tc8::ets::EtsTypes::UInt8Array> _data,
    echoUINT8Array2DimReply_t _reply) {
    _reply(_data);
}

void EtsImpl::echoUINT8Array(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    std::vector<uint8_t> _data,
    echoUINT8ArrayReply_t _reply) {
    _reply(_data);
}

void EtsImpl::echoUINT8Array16BitLength(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    std::vector<uint8_t> _data,
    echoUINT8Array16BitLengthReply_t _reply) {
    _reply(_data);
}

void EtsImpl::echoUINT8Array8BitLength(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    std::vector<uint8_t> _data,
    echoUINT8Array8BitLengthReply_t _reply) {
    _reply(_data);
}

void EtsImpl::echoUINT8ArrayMinSize(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    std::vector<uint8_t> _data,
    echoUINT8ArrayMinSizeReply_t _reply) {
    _reply(_data);
}

void EtsImpl::echoENUM(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    ::v1::org::tc8::ets::EnhancedTestability::EtsEnum _value,
    echoENUMReply_t _reply) {
    _reply(_value);
}

void EtsImpl::echoUTF16DYNAMIC(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    std::string _value,
    echoUTF16DYNAMICReply_t _reply) {
    _reply(_value);
}

void EtsImpl::echoUTF16FIXED(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    std::string _value,
    echoUTF16FIXEDReply_t _reply) {
    _reply(_value);
}

void EtsImpl::echoUTF8DYNAMIC(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    std::string _value,
    echoUTF8DYNAMICReply_t _reply) {
    _reply(_value);
}

void EtsImpl::echoUTF8FIXED(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    std::string _value,
    echoUTF8FIXEDReply_t _reply) {
    _reply(_value);
}

namespace {

// Width-specific bit reversal helpers used by §5.1.6 SOMEIP_ETS_007
// echoBitfields. Each reverses the bit order within the integer's
// underlying byte width — i.e. bit 0 ↔ bit (W-1).
constexpr uint8_t reverseBits8(uint8_t v) {
    v = static_cast<uint8_t>(((v & 0xF0u) >> 4) | ((v & 0x0Fu) << 4));
    v = static_cast<uint8_t>(((v & 0xCCu) >> 2) | ((v & 0x33u) << 2));
    v = static_cast<uint8_t>(((v & 0xAAu) >> 1) | ((v & 0x55u) << 1));
    return v;
}

constexpr uint16_t reverseBits16(uint16_t v) {
    v = static_cast<uint16_t>(((v & 0xFF00u) >> 8) | ((v & 0x00FFu) << 8));
    v = static_cast<uint16_t>(((v & 0xF0F0u) >> 4) | ((v & 0x0F0Fu) << 4));
    v = static_cast<uint16_t>(((v & 0xCCCCu) >> 2) | ((v & 0x3333u) << 2));
    v = static_cast<uint16_t>(((v & 0xAAAAu) >> 1) | ((v & 0x5555u) << 1));
    return v;
}

constexpr uint32_t reverseBits32(uint32_t v) {
    v = ((v & 0xFFFF0000u) >> 16) | ((v & 0x0000FFFFu) << 16);
    v = ((v & 0xFF00FF00u) >>  8) | ((v & 0x00FF00FFu) <<  8);
    v = ((v & 0xF0F0F0F0u) >>  4) | ((v & 0x0F0F0F0Fu) <<  4);
    v = ((v & 0xCCCCCCCCu) >>  2) | ((v & 0x33333333u) <<  2);
    v = ((v & 0xAAAAAAAAu) >>  1) | ((v & 0x55555555u) <<  1);
    return v;
}

}  // namespace

void EtsImpl::echoBitfields(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint8_t _arg1,
    uint16_t _arg2,
    uint32_t _arg3,
    echoBitfieldsReply_t _reply) {
    _reply(reverseBits8(_arg1), reverseBits16(_arg2), reverseBits32(_arg3));
}

void EtsImpl::echoUINT8E2E(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint32_t _len,
    uint32_t _counter,
    uint32_t _dataID,
    uint32_t _crc,
    uint8_t _value,
    echoUINT8E2EReply_t _reply) {
    _reply(_len, _counter, _dataID, _crc, _value);
}

void EtsImpl::echoUNION(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    ::v1::org::tc8::ets::EtsTypes::EtsUnion _value,
    echoUNIONReply_t _reply) {
    _reply(_value);
}

void EtsImpl::clientServiceActivate(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint8_t _delay) {
    if (clientProxyModeEnabled()) {
        client_mode_proxy_.start();
    } else {
        client_mode_.start(_delay);
    }
}

void EtsImpl::clientServiceDeactivate(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint8_t /*_delay*/) {
    if (clientProxyModeEnabled()) {
        client_mode_proxy_.stop();
    } else {
        client_mode_.stop();
    }
}

void EtsImpl::clientServiceSubscribeEventgroup(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint32_t _delay,
    uint32_t /*_duration*/) {
    if (!clientProxyModeEnabled()) {
        // Spec doesn't require any side-effect from this method when the
        // DUT is not in Proxy client mode; leaving it as a quiet no-op
        // keeps the ETS_098..101 path's stimulus chain unbroken if a
        // future case stacks Method 0x32 alongside Method 0x2F.
        return;
    }
    if (_delay > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(_delay));
    }
    if (clientProxyModeUdpEnabled()) {
        client_mode_proxy_.subscribeUdp();
    } else {
        client_mode_proxy_.subscribe();
    }
}

// §5.1.6 SOMEIP_ETS_103/_104/_105 last-value getters. Each returns the
// pre-initialised cell (0x08) — wire-shape valid, state-receipt vacuous.
void EtsImpl::clientServiceGetLastValueOfEventTCP(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    clientServiceGetLastValueOfEventTCPReply_t _reply) {
    _reply(lastEventValueTcp_);
}

void EtsImpl::clientServiceGetLastValueOfEventUDPUnicast(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    clientServiceGetLastValueOfEventUDPUnicastReply_t _reply) {
    _reply(lastEventValueUdpUnicast_);
}

void EtsImpl::clientServiceGetLastValueOfEventUDPMulticast(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    clientServiceGetLastValueOfEventUDPMulticastReply_t _reply) {
    _reply(lastEventValueUdpMulticast_);
}

void EtsImpl::suspendInterface(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/,
    uint32_t _start,
    uint32_t _duration) {
    if (suspend_callback_) {
        suspend_callback_(_start, _duration);
    }
}

void EtsImpl::resetInterface(
    const std::shared_ptr<CommonAPI::ClientId> /*_client*/) {
    fieldA_ = 0;
}

}  // namespace tc8::dut
