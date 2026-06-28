#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

// Single emission engine for the OA TC8 v3.0 ETS DUT. There is exactly ONE
// producer per event (no dual-path), fired from one tick thread. Two source
// kinds:
//   - cyclic   : free-running at a fixed period from start() — the legacy
//                unconditional TestEventUINT8 (0x8001) cadence the existing
//                conformance suite depends on.
//   - triggered: fires ONLY after onTrigger(), governed by the EmissionPolicy
//                (TestEventUINT8Array/E2E/Reliable/Multicast). A source that is
//                never triggered never fires — which is what lets the
//                "must-NOT-send" negative cases hold.
// The emit closure receives a per-source monotonically increasing payload byte
// OWNED by the controller (no hidden function-local statics).
namespace tc8::dut {

// Canonical emission-source names — the SSOT shared by EtsImpl (which arms a
// source from its triggerEventX Method) and dut_main (which binds each name to
// the matching CommonAPI fireTestEventXEvent). kArray/kReliable/kE2E/kMulticast
// are the OA TC8 v3.0 Table 2 trigger-driven events. kBasic (0x8001) is CYCLIC
// in the public DUT but is registered as a triggered source when an OEM opts in
// via IEtsExtension::ets8001TriggerDriven(); naming it here lets
// EtsImpl::triggerEventUINT8 arm it through the same path as the other four (a
// no-op while it stays cyclic, since the controller skips a due name that has no
// triggered source).
namespace ets_event {
inline constexpr std::string_view kBasic     = "TestEventUINT8";
inline constexpr std::string_view kArray     = "TestEventUINT8Array";
inline constexpr std::string_view kReliable  = "TestEventUINT8Reliable";
inline constexpr std::string_view kE2E       = "TestEventUINT8E2E";
inline constexpr std::string_view kMulticast = "TestEventUINT8Multicast";
}  // namespace ets_event

// WHEN each trigger-gated source fires. The wire args arrive as the strong
// chrono types below so a caller cannot pass them in the wrong unit; the
// uint32->chrono conversion (and its unit assumption) lives at the EtsImpl wire
// boundary, not here. Override point for an OEM whose timing semantics differ.
class EmissionPolicy {
public:
    virtual ~EmissionPolicy() = default;
    virtual void onTrigger(std::string_view source, std::chrono::seconds start,
                           std::chrono::seconds duration,
                           std::chrono::milliseconds period) = 0;
    // Names of the sources whose next fire time has arrived at `now`.
    virtual std::vector<std::string> due(std::chrono::steady_clock::time_point now) = 0;
};

// Default OA TC8 trigger semantics: after `start`, fire every `period` until
// `duration` has elapsed; `period <= 0` or `duration == 0` => single shot.
class DefaultTriggerPolicy : public EmissionPolicy {
public:
    void onTrigger(std::string_view source, std::chrono::seconds start,
                   std::chrono::seconds duration,
                   std::chrono::milliseconds period) override;
    std::vector<std::string> due(std::chrono::steady_clock::time_point now) override;

private:
    struct Arm {
        std::chrono::steady_clock::time_point next;
        std::chrono::steady_clock::time_point end;
        std::chrono::milliseconds period;
    };
    std::mutex mutex_;
    std::unordered_map<std::string, Arm> arms_;
};

class EmissionController {
public:
    EmissionController();
    ~EmissionController();
    EmissionController(const EmissionController&) = delete;
    EmissionController& operator=(const EmissionController&) = delete;

    // Free-running source: fires every `period` from start(). Add before start().
    void addCyclicSource(std::string name, std::function<void(uint8_t)> emit,
                         std::chrono::milliseconds period);
    // Trigger-gated source: fires only when the policy says so. Add before start().
    void addTriggeredSource(std::string name, std::function<void(uint8_t)> emit);
    // OEM override of the trigger policy. Must be called before start() (the
    // tick thread reads policy_ locklessly; swapping it live would race).
    void installPolicy(std::unique_ptr<EmissionPolicy> policy);
    // Forward a triggerEventX Method call to the policy.
    void onTrigger(std::string_view source, std::chrono::seconds start,
                   std::chrono::seconds duration, std::chrono::milliseconds period);
    void start();
    void stop();

    // One scheduling pass at logical time `now`. run() calls this every tick;
    // exposed so unit tests can drive the engine deterministically (no sleeps).
    void step(std::chrono::steady_clock::time_point now);

private:
    void run();
    struct Cyclic {
        std::string name;
        std::function<void(uint8_t)> emit;
        std::chrono::milliseconds period;
        std::chrono::steady_clock::time_point next;
        bool primed = false;
        uint8_t counter = 0;
    };
    struct Triggered {
        std::function<void(uint8_t)> emit;
        uint8_t counter = 0;
    };
    std::vector<Cyclic> cyclic_;
    std::unordered_map<std::string, Triggered> triggered_;
    std::unique_ptr<EmissionPolicy> policy_;
    std::thread thread_;
    std::atomic<bool> stop_{false};
};

}  // namespace tc8::dut
