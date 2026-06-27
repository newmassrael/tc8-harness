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

// Trigger-driven event emission for the OA TC8 v3.0 ETS (Table 1
// p413). The four new events (TestEventUINT8Array/E2E/Reliable/Multicast) fire
// ONLY in response to their triggerEventX Method — never on a free-running
// timer — which is exactly what lets the "must-NOT-send" negative cases hold.
// The legacy unconditional cyclic emission of TestEventUINT8 (0x8001) is left
// untouched in dut_main so the existing conformance suite is unaffected; 0x8001
// is ALSO registered here so triggerEventUINT8 is spec-faithful (extra fires
// during a trigger window are harmless atop the legacy cadence).
//
// OEM override: install a custom EmissionPolicy (different unit/debounce/keep-
// alive semantics) before start(). See
// claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
namespace tc8::dut {

// Canonical source names — the SSOT shared by EtsImpl (which arms a source from
// its triggerEventX Method) and dut_main (which binds each name to the matching
// CommonAPI fireTestEventXEvent). One constant per OA TC8 v3.0 Table 2 event.
namespace ets_event {
inline constexpr std::string_view kUint8     = "TestEventUINT8";
inline constexpr std::string_view kArray     = "TestEventUINT8Array";
inline constexpr std::string_view kReliable  = "TestEventUINT8Reliable";
inline constexpr std::string_view kE2E       = "TestEventUINT8E2E";
inline constexpr std::string_view kMulticast = "TestEventUINT8Multicast";
}  // namespace ets_event

// WHEN each named event source fires. Override point for an OEM that needs
// different timing semantics than the OA TC8 default (Table 1 p413).
class EmissionPolicy {
public:
    virtual ~EmissionPolicy() = default;
    // A triggerEventX(start, duration, debounceTime) Method was invoked.
    virtual void onTrigger(std::string_view source, uint32_t start,
                           uint32_t duration, uint32_t debounceTime) = 0;
    // Names of the sources whose next fire time has arrived at `now`.
    virtual std::vector<std::string> due(std::chrono::steady_clock::time_point now) = 0;
};

// OA TC8 v3.0 Table 3 (p421-440) semantics: after `start` SECONDS, fire the
// event periodically every `debounceTime` MILLISECONDS, until `duration`
// SECONDS have elapsed. A source that was never triggered never fires.
// (debounceTime == 0 or duration == 0 -> single shot.)
class DefaultTriggerPolicy : public EmissionPolicy {
public:
    void onTrigger(std::string_view source, uint32_t start,
                   uint32_t duration, uint32_t debounceTime) override;
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

// Owns a tick thread; binds each event source name to its emit closure and asks
// the policy which sources are due. Thread-safe for onTrigger() from the vsomeip
// dispatcher thread vs the tick thread (the policy guards its own state).
// installPolicy()/addSource() must be called before start().
class EmissionController {
public:
    EmissionController();
    ~EmissionController();
    EmissionController(const EmissionController&) = delete;
    EmissionController& operator=(const EmissionController&) = delete;

    // Bind a source name to the closure that fires the CommonAPI event.
    void addSource(std::string name, std::function<void()> emit);
    // Replace the default policy (OEM override). Call before start().
    void installPolicy(std::unique_ptr<EmissionPolicy> policy);
    // Forward a triggerEventX Method call to the policy.
    void onTrigger(std::string_view source, uint32_t start,
                   uint32_t duration, uint32_t debounceTime);
    void start();
    void stop();

private:
    void run();
    std::unordered_map<std::string, std::function<void()>> sources_;
    std::unique_ptr<EmissionPolicy> policy_;
    std::thread thread_;
    std::atomic<bool> stop_{false};
};

}  // namespace tc8::dut
