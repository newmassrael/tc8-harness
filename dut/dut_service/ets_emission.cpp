#include "ets_emission.h"

#include <cassert>
#include <utility>

namespace tc8::dut {

void DefaultTriggerPolicy::onTrigger(std::string_view source,
                                     std::chrono::seconds start,
                                     std::chrono::seconds duration,
                                     std::chrono::milliseconds period) {
    const auto now = std::chrono::steady_clock::now();
    const auto fire_start = now + start;
    Arm arm;
    arm.next = fire_start;
    arm.end = fire_start + duration;
    arm.period = period;
    std::lock_guard<std::mutex> lock(mutex_);
    arms_[std::string(source)] = arm;  // re-trigger replaces the prior arm
}

std::vector<std::string> DefaultTriggerPolicy::due(
    std::chrono::steady_clock::time_point now) {
    std::vector<std::string> ready;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = arms_.begin(); it != arms_.end();) {
        Arm& arm = it->second;
        if (now < arm.next) {
            ++it;
            continue;
        }
        // At/after the scheduled beat: fire FIRST, then decide continuation.
        // Firing before the window-end test is what makes a zero-duration arm
        // (next == end) fire its single beat instead of being erased unfired.
        ready.push_back(it->first);
        if (arm.period <= std::chrono::milliseconds(0) || now >= arm.end) {
            it = arms_.erase(it);  // single shot, or emission window finished
            continue;
        }
        arm.next += arm.period;
        if (arm.next <= now) {
            arm.next = now + arm.period;  // fell behind after a stall: drop missed beats
        }
        ++it;
    }
    return ready;
}

EmissionController::EmissionController()
    : policy_(std::make_unique<DefaultTriggerPolicy>()) {}

EmissionController::~EmissionController() { stop(); }

void EmissionController::addCyclicSource(std::string name,
                                        std::function<void(uint8_t)> emit,
                                        std::chrono::milliseconds period) {
    cyclic_.push_back(Cyclic{std::move(name), std::move(emit), period, {}, false, 0});
}

void EmissionController::addTriggeredSource(std::string name,
                                           std::function<void(uint8_t)> emit) {
    triggered_.emplace(std::move(name), Triggered{std::move(emit), 0});
}

void EmissionController::installPolicy(std::unique_ptr<EmissionPolicy> policy) {
    // The tick thread reads policy_ without a lock, so the swap is only safe
    // before the thread exists. Fail fast on misuse rather than trusting the
    // documented precondition.
    assert(!thread_.joinable() && "installPolicy must be called before start()");
    if (policy) {
        policy_ = std::move(policy);
    }
}

void EmissionController::onTrigger(std::string_view source,
                                  std::chrono::seconds start,
                                  std::chrono::seconds duration,
                                  std::chrono::milliseconds period) {
    policy_->onTrigger(source, start, duration, period);
}

void EmissionController::step(std::chrono::steady_clock::time_point now) {
    for (Cyclic& c : cyclic_) {
        if (!c.primed) {  // first pass: schedule the first beat one period out
            c.next = now + c.period;
            c.primed = true;
            continue;
        }
        if (now < c.next) {
            continue;
        }
        c.emit(c.counter++);
        c.next += c.period;
        if (c.next <= now) {
            c.next = now + c.period;  // resync after a stall
        }
    }
    for (const std::string& name : policy_->due(now)) {
        auto it = triggered_.find(name);
        if (it != triggered_.end()) {
            it->second.emit(it->second.counter++);
        }
    }
}

void EmissionController::start() {
    stop_.store(false);
    thread_ = std::thread([this] { run(); });
}

void EmissionController::stop() {
    stop_.store(true);
    if (thread_.joinable()) {
        thread_.join();
    }
}

void EmissionController::run() {
    using namespace std::chrono_literals;
    while (!stop_.load()) {
        step(std::chrono::steady_clock::now());
        // 20 ms poll: << the per-second observation windows the spec uses, so
        // emission jitter is immaterial; cheap enough to leave running idle.
        std::this_thread::sleep_for(20ms);
    }
}

}  // namespace tc8::dut
