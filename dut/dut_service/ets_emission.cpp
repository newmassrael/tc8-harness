#include "ets_emission.h"

#include <cassert>
#include <utility>

namespace tc8::dut {

namespace {

// `count` units of `unit`. A UInt32 count times a unit of at most a day stays far
// inside the 64-bit millisecond range, so the product cannot overflow.
std::chrono::milliseconds scaled(std::uint32_t count, std::chrono::milliseconds unit) {
    return std::chrono::milliseconds(static_cast<std::int64_t>(count) * unit.count());
}

}  // namespace

void DefaultTriggerPolicy::onTrigger(std::string_view source, const TriggerArguments& args,
                                     EmissionClock::time_point now) {
    const auto fire_start = now + scaled(args.start, units_.start);
    Arm arm;
    arm.next = fire_start;
    arm.end = fire_start + scaled(args.duration, units_.duration);
    arm.period = scaled(args.debounce_time, units_.debounce_time);
    std::lock_guard<std::mutex> lock(mutex_);
    arms_[std::string(source)] = arm;  // re-trigger replaces the prior arm
}

std::vector<Emission> DefaultTriggerPolicy::due(EmissionClock::time_point now) {
    std::vector<Emission> ready;
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
        ready.push_back(Emission{it->first, values_[it->first]++});
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

void SequentialTriggerPolicy::onTrigger(std::string_view source, const TriggerArguments& args,
                                        EmissionClock::time_point now) {
    std::lock_guard<std::mutex> lock(mutex_);
    loops_[std::string(source)].pending.push_back(Pending{args, now});
}

void SequentialTriggerPolicy::begin(Loop& loop, const Pending& trigger) const {
    // A trigger that waited for a running loop starts when that loop ended, not when it arrived.
    const auto from = trigger.received > loop.free_since ? trigger.received : loop.free_since;
    loop.first_beat = from + scaled(trigger.args.start, units_.start);
    loop.duration = scaled(trigger.args.duration, units_.duration);
    const auto period = scaled(trigger.args.debounce_time, units_.debounce_time);
    loop.period = period > std::chrono::milliseconds(0) ? period : zero_debounce_;
    loop.value = 1;
    loop.next_beat = loop.first_beat;
    loop.running = true;
    loop.beats_left = trigger.args.duration > 0;  // a zero duration sends nothing
    loop.busy_until = loop.first_beat;
}

std::vector<Emission> SequentialTriggerPolicy::due(EmissionClock::time_point now) {
    std::vector<Emission> ready;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [source, loop] : loops_) {
        for (;;) {
            if (!loop.running) {
                if (loop.pending.empty()) {
                    break;
                }
                begin(loop, loop.pending.front());
                loop.pending.pop_front();
            }
            if (loop.beats_left && now >= loop.next_beat) {
                ready.push_back(Emission{source, loop.value++});
                loop.next_beat += loop.period;
                // The elapsed time is checked after the debounce wait that follows each event.
                if (loop.next_beat - loop.first_beat >= loop.duration) {
                    loop.beats_left = false;
                    loop.busy_until = loop.next_beat;
                }
                continue;
            }
            if (!loop.beats_left && now >= loop.busy_until) {
                loop.running = false;  // this loop is over; a queued trigger starts from here
                loop.free_since = loop.busy_until;
                continue;
            }
            break;
        }
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
    triggered_.emplace(std::move(name), std::move(emit));
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

void EmissionController::onTrigger(std::string_view source, const TriggerArguments& args) {
    policy_->onTrigger(source, args, EmissionClock::now());
}

void EmissionController::step(EmissionClock::time_point now) {
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
    for (const Emission& e : policy_->due(now)) {
        auto it = triggered_.find(e.source);
        if (it != triggered_.end()) {
            it->second(e.value);
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
        step(EmissionClock::now());
        // 20 ms poll: << the per-second observation windows the spec uses, so
        // emission jitter is immaterial; cheap enough to leave running idle.
        std::this_thread::sleep_for(20ms);
    }
}

}  // namespace tc8::dut
