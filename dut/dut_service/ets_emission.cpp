#include "ets_emission.h"

#include <utility>

namespace tc8::dut {

void DefaultTriggerPolicy::onTrigger(std::string_view source, uint32_t start,
                                     uint32_t duration, uint32_t debounceTime) {
    const auto now = std::chrono::steady_clock::now();
    const auto fire_start = now + std::chrono::seconds(start);
    Arm arm;
    arm.next = fire_start;
    arm.end = fire_start + std::chrono::seconds(duration);
    arm.period = std::chrono::milliseconds(debounceTime);
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
        if (now > arm.end) {  // emission window finished
            it = arms_.erase(it);
            continue;
        }
        ready.push_back(it->first);
        if (arm.period <= std::chrono::milliseconds(0)) {
            it = arms_.erase(it);  // single shot
            continue;
        }
        arm.next += arm.period;
        ++it;
    }
    return ready;
}

EmissionController::EmissionController()
    : policy_(std::make_unique<DefaultTriggerPolicy>()) {}

EmissionController::~EmissionController() { stop(); }

void EmissionController::addSource(std::string name, std::function<void()> emit) {
    sources_.emplace(std::move(name), std::move(emit));
}

void EmissionController::installPolicy(std::unique_ptr<EmissionPolicy> policy) {
    if (policy) {
        policy_ = std::move(policy);
    }
}

void EmissionController::onTrigger(std::string_view source, uint32_t start,
                                   uint32_t duration, uint32_t debounceTime) {
    policy_->onTrigger(source, start, duration, debounceTime);
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
        for (const std::string& name : policy_->due(std::chrono::steady_clock::now())) {
            auto it = sources_.find(name);
            if (it != sources_.end()) {
                it->second();
            }
        }
        // 20 ms poll: << the per-second observation windows the spec uses, so
        // emission jitter is immaterial; cheap enough to leave running idle.
        std::this_thread::sleep_for(20ms);
    }
}

}  // namespace tc8::dut
