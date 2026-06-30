#pragma once

#include <memory>

#include "ets_emission.h"

// Forward-declared so this header stays free of the heavy CommonAPI include; the
// shared_ptr<CommonAPI::Runtime> member only needs a complete type where
// ServerRole's (out-of-line) destructor is instantiated — server_role.cpp.
namespace CommonAPI {
class Runtime;
}

namespace tc8::dut {

class IEtsExtension;
class EtsImpl;
class Ets2Impl;

// SOME/IP deployment identity for the ETS server role, shared by ServerRole
// (which offers these services) and dut_main (whose client-only message names the
// primary interface it deliberately does NOT offer). NOTE: these are a hand-kept
// MIRROR of the authoritative deployment (commonapi.ini + dut/ets/*.fdepl), not a
// source of truth — there is no automated cross-check yet, so keep them in step
// with that config by hand. This is the same standing debt dut_config.h documents
// for the numeric kServiceId/kInstanceId; a future codegen pass should subsume
// both sides.
namespace ets_deploy {
inline constexpr const char* kDomain    = "local";
inline constexpr const char* kInstance  = "ETS";
inline constexpr const char* kInterface = "org.tc8.ets.EnhancedTestability:v1_0";
// SERVICE-ID-1 second instance (multi-instance axis: §5.1.5.3 SD_MESSAGE_01/_02 +
// §5.1.5.7 RPC_14/_17). Gated on TC8_DUT_INSTANCE_2.
inline constexpr const char* kInstance2 = "ETS2";
// SERVICE-ID-2 (multi-service axis: §5.1.5.7 RPC_01/_02/_13) — a distinct
// SomeIpServiceID (0xF4E8) on the same domain. Gated on TC8_DUT_SERVICE_2.
inline constexpr const char* kInstanceSi2  = "ETS_SI2";
inline constexpr const char* kInterfaceSi2 = "org.tc8.ets2.EnhancedTestability2:v1_0";
}  // namespace ets_deploy

// The DUT's SERVER role: everything that exists ONLY when the DUT offers the ETS
// service — i.e. NOT in the client-only (CLT) topology. Bundles the registered
// primary stub, the optional second instance / second service, the single
// event-emission engine, and the suspendInterface re-offer wiring into one
// object, so dut_main no longer threads scattered `if (!client_only)` guards
// through its flat scope. Constructing one IS "take the server role"; not
// constructing one IS client-only mode.
//
// Lifecycle is driven EXPLICITLY by dut_main, not via RAII: the DUT exits through
// std::_Exit (skipping destructors), so teardown must be called, never relied on.
// The phase methods keep their exact pre-extraction call sites, so no wire timing
// moves relative to the shared UT / testability / onStop sequence:
//   ctor           : register service(s) + wire emission sources + suspend callback
//   startEmission(): begin the cyclic / triggered Notification cadence
//   stopEmission() : halt the cadence (before the shared shutdown hooks)
//   unregisterAll(): StopOfferService for every offered instance/service
//
// Construction registers the primary service synchronously, which is what creates
// the backing CommonAPI-owned vsomeip application — so a ServerRole MUST be
// constructed before makeEtsEventSink / makeEtsClientControl, which retrieve that
// application by connection id (see ets_vsomeip_app.h). A registration failure
// hard-exits (std::_Exit(1)), upholding the DUT invariant of never running static
// destructors against a half-initialised routing manager.
class ServerRole {
public:
    // `runtime` is the process CommonAPI runtime. `extension` is queried once for
    // ets8001TriggerDriven() to pick the 0x8001 source kind (cyclic vs triggered);
    // it is not retained. MAY NOT RETURN: a registration failure calls
    // std::_Exit(1) (see the class note on the half-init routing-manager hazard),
    // so `server.emplace(...)` at the call site can terminate the process.
    ServerRole(std::shared_ptr<CommonAPI::Runtime> runtime, const IEtsExtension& extension);
    ~ServerRole();

    ServerRole(const ServerRole&)            = delete;
    ServerRole& operator=(const ServerRole&) = delete;

    // Begin the Notification cadence. Called once, after the shared seam +
    // upper-tester + testability bring-up, at the same point the pre-extraction
    // dut_main called emission.start().
    void startEmission();
    // Halt the cadence, before the shared onStop / testability.stop / UT.stop.
    void stopEmission();
    // StopOfferService for the second service, second instance, then the primary —
    // the teardown order of the pre-extraction dut_main.
    void unregisterAll();

private:
    std::shared_ptr<CommonAPI::Runtime> runtime_;
    std::shared_ptr<EtsImpl>  impl_;      // primary registered stub
    std::shared_ptr<EtsImpl>  impl2_;     // optional second instance (TC8_DUT_INSTANCE_2)
    std::shared_ptr<Ets2Impl> impl_si2_;  // optional second service  (TC8_DUT_SERVICE_2)
    EmissionController emission_;
};

}  // namespace tc8::dut
