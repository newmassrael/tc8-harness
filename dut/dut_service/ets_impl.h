#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <v1/org/tc8/ets/EnhancedTestabilityStubDefault.hpp>
#include <v1/org/tc8/ets/EtsTypes.hpp>

#include "client_mode.h"
#include "client_mode_proxy.h"

namespace tc8::dut {

class EmissionController;

// ETS MVP implementation — only overrides where spec-defined behaviour
// differs from the generated default (which simply echoes zero-initialised
// out-parameters). Other methods fall through to StubDefault until B-2
// expands coverage.
class EtsImpl : public v1::org::tc8::ets::EnhancedTestabilityStubDefault {
public:
    EtsImpl() = default;

    // TC8 §5.1.4.4.1 checkByteOrder: DUT returns summandUINT8 + summandUINT16
    // as UInt32, serialised big-endian by the SOME/IP stack.
    void checkByteOrder(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint8_t _summandUINT8,
        uint16_t _summandUINT16,
        checkByteOrderReply_t _reply) override;

    // Primitive echoes — input forwarded to the reply callback.
    void echoUINT8(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint8_t _value,
        echoUINT8Reply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_008 echoCommonDatatypes — Response args are
    // the Request args in REVERSED order (res1 = arg9, res2 = arg8,
    // ..., res9 = arg1) per ets.fidl interface spec. StubDefault would
    // zero-initialise out-params, which trivially passes for an
    // all-zero stimulus but cannot verify reversal; this override
    // makes the echo verifiable end-to-end.
    void echoCommonDatatypes(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        bool _arg1,
        uint8_t _arg2,
        uint16_t _arg3,
        uint32_t _arg4,
        int8_t _arg5,
        int16_t _arg6,
        int32_t _arg7,
        float _arg8,
        double _arg9,
        echoCommonDatatypesReply_t _reply) override;

    void echoUINT8RELIABLE(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint8_t _value,
        echoUINT8RELIABLEReply_t _reply) override;

    void echoINT8(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        int8_t _value,
        echoINT8Reply_t _reply) override;

    // §5.1.5.7 RPC_03 / RPC_11 — getter/setter pair backed by a single
    // UInt8 cell. getFieldA returns the most recently set value;
    // setFieldA stores the new value and echoes it on the wire. Default-
    // initialised to 0 so the getter has a well-defined response before
    // any setter call.
    void getFieldA(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        getFieldAReply_t _reply) override;

    void setFieldA(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint8_t _value,
        setFieldAReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_167 TestFieldUINT8Array — UInt8[] field with
    // getter (Method 0x28) + setter (Method 0x29). UDP transport.
    // Backed by `testFieldUint8Array_` (default-initialised to empty).
    void getTestFieldUint8Array(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        getTestFieldUint8ArrayReply_t _reply) override;

    void setTestFieldUint8Array(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        std::vector<uint8_t> _data,
        setTestFieldUint8ArrayReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_168 TestFieldUINT8Reliable — UInt8 field over TCP
    // (SomeIpReliable=true on Method 0x2A getter / 0x2B setter). Backed
    // by `testFieldUint8Reliable_` (default 0).
    void getTestFieldUint8Reliable(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        getTestFieldUint8ReliableReply_t _reply) override;

    void setTestFieldUint8Reliable(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint8_t _value,
        setTestFieldUint8ReliableReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_019 echoFLOAT64 — Double round-trip echo.
    void echoFLOAT64(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        double _value,
        echoFLOAT64Reply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_022 echoStaticUINT8Array — fixed-size 5-element
    // UInt8 array round-trip (no wire length prefix).
    void echoStaticUINT8Array(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        std::vector<uint8_t> _data,
        echoStaticUINT8ArrayReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_030 echoUINT8Array2Dim — vector of UInt8Array
    // round-trip echo. The element typedef
    // `v1::org::tc8::ets::EtsTypes::UInt8Array` is a CommonAPI-generated
    // alias for `std::vector<uint8_t>`.
    void echoUINT8Array2Dim(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        std::vector<v1::org::tc8::ets::EtsTypes::UInt8Array> _data,
        echoUINT8Array2DimReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_028..033 array-echo overrides — StubDefault
    // returns a default-constructed (empty) vector for the out-param,
    // which would never let a tester verify the echo round-trip.
    void echoUINT8Array(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        std::vector<uint8_t> _data,
        echoUINT8ArrayReply_t _reply) override;

    void echoUINT8Array16BitLength(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        std::vector<uint8_t> _data,
        echoUINT8Array16BitLengthReply_t _reply) override;

    void echoUINT8Array8BitLength(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        std::vector<uint8_t> _data,
        echoUINT8Array8BitLengthReply_t _reply) override;

    void echoUINT8ArrayMinSize(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        std::vector<uint8_t> _data,
        echoUINT8ArrayMinSizeReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_009 echoENUM — 1-byte enum round-trip.
    void echoENUM(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        ::v1::org::tc8::ets::EnhancedTestability::EtsEnum _value,
        echoENUMReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_039 echoUTF16DYNAMIC — UTF-16 BE dynamic string
    // round-trip echo.
    void echoUTF16DYNAMIC(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        std::string _value,
        echoUTF16DYNAMICReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_046 echoUTF16FIXED — UTF-16 BE 64-byte fixed
    // string round-trip echo.
    void echoUTF16FIXED(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        std::string _value,
        echoUTF16FIXEDReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_048 echoUTF8DYNAMIC — UTF-8 dynamic string
    // round-trip echo.
    void echoUTF8DYNAMIC(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        std::string _value,
        echoUTF8DYNAMICReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_053 echoUTF8FIXED — UTF-8 64-byte fixed string
    // round-trip echo.
    void echoUTF8FIXED(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        std::string _value,
        echoUTF8FIXEDReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_007 echoBitfields — three bit-reversed integer
    // args. Spec p401-420 mandates ResArgN = "reversed bit order of
    // ReqArgN" so the DUT mutates the bits rather than echoing
    // unchanged. Reverses are width-specific (Uint8 = 8 bits,
    // Uint16 = 16 bits, Uint32 = 32 bits).
    void echoBitfields(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint8_t _arg1,
        uint16_t _arg2,
        uint32_t _arg3,
        echoBitfieldsReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_034 echoUINT8E2E — 5-arg echo. The 4×UInt32
    // E2E header fields (len, counter, dataID, crc) and the UInt8
    // value all round-trip unchanged.
    void echoUINT8E2E(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint32_t _len,
        uint32_t _counter,
        uint32_t _dataID,
        uint32_t _crc,
        uint8_t _value,
        echoUINT8E2EReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_038 echoUNION — discriminated-union round-trip
    // echo. The CommonAPI-generated `EtsUnion` is a
    // `CommonAPI::Variant<bool, uint8_t, uint16_t, uint32_t, int8_t,
    //  int16_t>`; the DUT replies with the same Variant.
    void echoUNION(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        ::v1::org::tc8::ets::EtsTypes::EtsUnion _value,
        echoUNIONReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_098..101 — clientServiceActivate spawns a raw-UDP
    // SD client that emits FindService for SERVICE-ID-2 during the Start-Up
    // Phase only (PRS_SOMEIPSD_00350/00351). Deactivate stops the runner;
    // the existing 472 server-side cases are unaffected because the runner
    // operates outside vsomeip's lifecycle (see client_mode.h). Both
    // methods are Fire&Forget (no Reply_t).
    void clientServiceActivate(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint8_t _delay) override;

    void clientServiceDeactivate(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint8_t _delay) override;

    // §5.1.6 SOMEIP_ETS_097 — Method 0x32. When TC8_DUT_CLIENT_MODE=1, this
    // method calls subscribe() on the ets3 ClientTarget proxy spawned by
    // clientServiceActivate; vsomeip then emits SubscribeEventgroup with a
    // TCP IPv4 Endpoint Option and attempts the TCP connect (auto-retried
    // on ECONNREFUSED via vsomeip client_endpoint_impl). Without the env
    // gate this method is a no-op so the existing ETS_098..101 raw-UDP
    // path is unaffected.
    void clientServiceSubscribeEventgroup(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint32_t _delay,
        uint32_t _duration) override;

    // §5.1.6 SOMEIP_ETS_103/_104/_105 — return the last UInt8 received
    // on the TCP-reliable / UDP-unicast / UDP-multicast target events.
    // Storage cells default to 0x08 (the spec's canonical test value);
    // the event-receive wiring that would update them from actual
    // Notification payloads is not implemented in tc8-dut, so the
    // response is wire-shape valid but state-receipt vacuous.
    void clientServiceGetLastValueOfEventTCP(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        clientServiceGetLastValueOfEventTCPReply_t _reply) override;

    void clientServiceGetLastValueOfEventUDPUnicast(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        clientServiceGetLastValueOfEventUDPUnicastReply_t _reply) override;

    void clientServiceGetLastValueOfEventUDPMulticast(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        clientServiceGetLastValueOfEventUDPMulticastReply_t _reply) override;

    // §5.1.6 SOMEIP_ETS_089 — TC8 §5.1.4.3.2 suspendInterface. The DUT
    // delays `_start` ms, stops offering its service (wire signal:
    // StopOfferService entry, ttl == 0), waits `_duration` ms, then
    // re-offers (wire signal: OfferService entry, ttl > 0). The actual
    // unregister + re-register call is delegated to a callback provided
    // by `dut_main` so the EtsImpl stays decoupled from the
    // CommonAPI::Runtime + impl shared_ptr ownership chain. When the
    // callback is unset (default), the override is a no-op so existing
    // cases that ignore suspendInterface stay green.
    void suspendInterface(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint32_t _start,
        uint32_t _duration) override;

    using SuspendCallback = std::function<void(uint32_t /*start_ms*/, uint32_t /*duration_ms*/)>;
    void setSuspendCallback(SuspendCallback cb) { suspend_callback_ = std::move(cb); }

    // §5.1.6 SOMEIP_ETS_146 — TC8 §5.1.4.3.1 resetInterface. Fire&Forget
    // method that brings the DUT's testable surface back to its initial
    // state. For the current cluster this is fieldA_ → 0; future
    // attributes added to ets.fidl should be reset here too. The
    // override is synchronous and idempotent so the test envelope's
    // 3 s post-reset wait covers any settling.
    void resetInterface(
        const std::shared_ptr<CommonAPI::ClientId> _client) override;

    // OA TC8 v3.0 Table 1 (p413) trigger methods. triggerEventUINT8 (0x8001) is
    // a documented no-op: 0x8001 is the DUT's free-running cyclic event (the
    // pre-existing CI cadence the suite relies on), so its trigger is satisfied
    // by the always-on emission. The other four forward to the EmissionController
    // via armEvent(). The argument unit conversion (and its assumption) lives in
    // armEvent, the single wire boundary.
    void triggerEventUINT8(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint32_t _start, uint32_t _duration, uint32_t _debounceTime) override;

    void triggerEventUINT8Array(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint32_t _start, uint32_t _duration, uint32_t _debounceTime) override;

    void triggerEventUINT8Reliable(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint32_t _start, uint32_t _duration, uint32_t _debounceTime) override;

    void triggerEventUINT8E2E(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint32_t _start, uint32_t _duration, uint32_t _debounceTime) override;

    void triggerEventUINT8Multicast(
        const std::shared_ptr<CommonAPI::ClientId> _client,
        uint32_t _start, uint32_t _duration, uint32_t _debounceTime) override;

    // Non-owning; set by dut_main after the controller is constructed. The
    // controller outlives the dispatcher threads that call the triggers.
    void setEmissionController(EmissionController* controller) {
        emission_ = controller;
    }

private:
    // Single wire boundary for the trigger args. UNIT ASSUMPTION: OA TC8 p425
    // states only `start` is in seconds; `duration`/`debounceTime` units are not
    // defined in the test-spec PDF (the OA service catalog is authoritative and
    // is not vendored here). We read start/duration as seconds and debounceTime
    // as the period; an OEM whose units differ installs its own EmissionPolicy.
    void armEvent(std::string_view source, uint32_t start, uint32_t duration,
                  uint32_t debounceTime);

    uint8_t fieldA_ = 0;
    std::vector<uint8_t> testFieldUint8Array_{};
    uint8_t testFieldUint8Reliable_ = 0;
    // §5.1.6 SOMEIP_ETS_103/_104/_105 — last-received UInt8 per
    // transport. Pre-initialised to the spec's test value (0x08) so the
    // GetLastValueOfEvent* Methods produce a wire-shape valid Response
    // even without the (not-implemented) event-receive wiring.
    uint8_t lastEventValueTcp_ = 0x08;
    uint8_t lastEventValueUdpUnicast_ = 0x08;
    uint8_t lastEventValueUdpMulticast_ = 0x08;
    ClientModeRunner client_mode_{};
    ClientModeProxyRunner client_mode_proxy_{};
    SuspendCallback suspend_callback_{};
    EmissionController* emission_ = nullptr;
};

}  // namespace tc8::dut
