#pragma once

#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <vector>

// The threading headers back the owned-thread start()/stop() and the cross-thread
// post(). A single-task (bare-metal / RTOS) build — where the toolchain's libstdc++
// is --disable-threads and <thread>/<mutex>/<future> are not even declared — defines
// TC8_REACTOR_SINGLE_THREAD to compile those out and drives the loop with
// open()/runOnce()/close() from its own task instead.
#ifndef TC8_REACTOR_SINGLE_THREAD
#include <future>
#include <mutex>
#include <thread>
#endif

#include "testability/io_multiplexer.h"  // Waker / IoMultiplexer (the ports it needs)
#include "testability/middleware.h"  // TimerId / WatchId / kNoTimer / kNoWatch

namespace tc8::testability {

// A single-threaded event-loop reactor: posted tasks, periodic/one-shot timers,
// and fd-readiness watches, all run run-to-completion on one owned thread, so a
// client carries no internal locks. The thread blocks in IoMultiplexer::poll over
// the watched fds plus the Waker, woken by (a) a watched fd becoming readable
// (genuine readiness — never a drain timer), (b) the next timer coming due (the
// poll timeout), or (c) the Waker, signalled after a cross-thread post() so a
// marshaled task runs promptly. Reusable and unit-testable in isolation against a
// fake IoMultiplexer — it has no dependency on the testability protocol or modules.
//
// Threading: post() is the only cross-thread entry (it marshals + blocks); timers
// and watches are mutated only on the loop thread (armEvery/armOnce/cancel/addWatch/
// removeWatch assert this), so only the task queue needs a lock.
class Reactor {
public:
    explicit Reactor(IoMultiplexer &mux) : mux_(mux) {}
    ~Reactor() {
#ifdef TC8_REACTOR_SINGLE_THREAD
        close();  // no thread to join
#else
        stop();  // idempotent; joins the thread if still running
#endif
    }
    Reactor(const Reactor &) = delete;
    Reactor &operator=(const Reactor &) = delete;

    // Liveness backstop: cap an otherwise-indefinite poll wait at this heartbeat so
    // a lost cross-thread wake (a Waker::signal() is best-effort — e.g. a droppable
    // loopback datagram) delays a posted task by at most this, never wedges it. NOT
    // rx polling: a watched fd's readiness still wakes poll() immediately.
    static constexpr int kBackstopMs = 1000;

#ifndef TC8_REACTOR_SINGLE_THREAD
    // Spawn the loop thread. createWaker() runs here (before the thread) so post()
    // can immediately signal it. (Owned-thread mode; unavailable single-task.)
    void start() {
        running_ = true;  // visible to the new thread (thread creation synchronises)
        waker_ = mux_.createWaker();
        thread_ = std::thread([this] { run(); });
        thread_id_ = thread_.get_id();
    }

    // Run `final_task` (if any) on the loop thread, then stop and join. Idempotent:
    // a no-op if never started or already stopped. The Waker is freed after the
    // join, so no concurrent poll can touch it.
    void stop(const std::function<void()> &final_task = {}) {
        if (!thread_.joinable()) {
            return;
        }
        post([&] {
            if (final_task) {
                final_task();
            }
            timers_.clear();   // nothing fires after the final task (loop-thread state)
            watches_.clear();
            running_ = false;  // exit the loop after this task
        });
        thread_.join();
        waker_.reset();
    }
#endif  // !TC8_REACTOR_SINGLE_THREAD

    // ── Caller-driven (single-task) mode: no owned thread ──
    // The alternative to start()/stop() for a deployment with no std::thread (a
    // bare-metal / RTOS target): the caller's own task initialises with open(),
    // pumps runOnce()/run() from that same task, and tears down with close(). Timers
    // and watches are then armed directly from that task (it IS the loop thread), so
    // no cross-thread post() is needed. open() and the pump MUST run on one task.
    void open() {
        running_ = true;
#ifndef TC8_REACTOR_SINGLE_THREAD
        waker_ = mux_.createWaker();
        thread_id_ = std::this_thread::get_id();  // the pumping task owns the loop
#endif
        // Single-task: no waker (nothing posts cross-thread) and no affinity id
        // (there is only one task) — poll() runs over the watched fds and timers.
    }

    // Caller-driven teardown: run `final_task` (if any) on the calling task, drop all
    // timers/watches, and mark the loop stopped. Idempotent; the counterpart of
    // stop() with no thread to join.
    void close(const std::function<void()> &final_task = {}) {
        if (!running_) {
            return;
        }
        if (final_task) {
            final_task();
        }
        timers_.clear();
        watches_.clear();
        running_ = false;
        waker_.reset();
    }

    // Enqueue `fn` and block until the loop runs it. Inline when already on the loop
    // thread so a re-entrant call cannot self-deadlock. The Waker breaks the loop
    // out of poll(); enqueue-before-signal means a signal landing before poll() just
    // leaves the wake fd readable, so the task is never lost (a dropped best-effort
    // signal only delays it to the next backstop wakeup).
    void post(const std::function<void()> &fn) {
#ifdef TC8_REACTOR_SINGLE_THREAD
        fn();  // single task: the caller is always the loop task — run inline
#else
        if (std::this_thread::get_id() == thread_id_) {
            fn();
            return;
        }
        std::promise<void> done;
        std::future<void> fut = done.get_future();
        {
            std::lock_guard<std::mutex> lk(mu_);
            tasks_.push_back([&] {
                fn();
                done.set_value();
            });
        }
        if (waker_) {
            waker_->signal();
        }
        fut.wait();
#endif
    }

    TimerId armEvery(std::chrono::milliseconds period, std::function<void()> fn) {
        return arm(period, std::move(fn), /*periodic=*/true);
    }
    TimerId armOnce(std::chrono::milliseconds delay, std::function<void()> fn) {
        return arm(delay, std::move(fn), /*periodic=*/false);
    }
    void cancel(TimerId id) {
        assertOnLoop();
        timers_.erase(static_cast<std::uint64_t>(id));  // loop-thread only, no lock
    }
    WatchId addWatch(int fd, std::function<void()> fn) {
        assertOnLoop();
        if (fd < 0) {
            return kNoWatch;
        }
        const std::uint64_t id = next_watch_id_++;
        watches_[id] = Watch{fd, std::move(fn)};  // picked up on the next poll
        return static_cast<WatchId>(id);
    }
    void removeWatch(WatchId id) {
        assertOnLoop();
        watches_.erase(static_cast<std::uint64_t>(id));  // loop-thread only, no lock
    }

    // True when called on the reactor's loop thread (the precondition for the
    // lock-free timer/watch mutators). Always true single-task (one task only).
    bool onLoop() const {
#ifdef TC8_REACTOR_SINGLE_THREAD
        return true;
#else
        return std::this_thread::get_id() == thread_id_;
#endif
    }

private:
    struct Timer {
        std::chrono::steady_clock::time_point next;
        std::chrono::milliseconds period;
        std::function<void()> fn;
        bool periodic;
    };
    struct Watch {
        int fd;
        std::function<void()> fn;
    };

    // The lock-free timer/watch state is safe only because every mutator runs on
    // the loop thread. Assert it in debug builds rather than trust the convention.
    void assertOnLoop() const {
#ifndef TC8_REACTOR_SINGLE_THREAD
        assert(std::this_thread::get_id() == thread_id_);
#endif
    }

    TimerId arm(std::chrono::milliseconds period, std::function<void()> fn, bool periodic) {
        assertOnLoop();
        const std::uint64_t id = next_timer_id_++;
        timers_[id] = Timer{std::chrono::steady_clock::now() + period, period, std::move(fn),
                            periodic};
        return static_cast<TimerId>(id);
    }

    // Run every queued task FIFO, then return.
    void drainTasks() {
        for (;;) {
            std::function<void()> t;
            {
#ifndef TC8_REACTOR_SINGLE_THREAD
                std::lock_guard<std::mutex> lk(mu_);
#endif
                if (tasks_.empty()) {
                    return;
                }
                t = std::move(tasks_.front());
                tasks_.pop_front();
            }
            t();  // outside the lock: a task may enqueue more / arm timers / watch
        }
    }

public:
    // Drive the loop to completion. Used by start()'s owned thread on a hosted
    // build; a caller-driven (single-task) deployment pumps runOnce() itself.
    void run() {
        while (running_) {
            runOnce(kBackstopMs);
        }
    }

    // One reactor iteration, factored out of run() so the same body serves both the
    // owned-thread loop and a caller-driven pump. It drains the task queue, then
    // EITHER fires the single earliest-due timer (returning at once so the next
    // iteration re-scans — a handler may have armed/cancelled timers) OR blocks in
    // poll() for at most `max_wait_ms` (further capped by the next timer's due time)
    // and dispatches the readable watches. Returns running_, so a pump can loop on
    // the result and observe a stop task promptly. `max_wait_ms` == 0 makes the poll
    // non-blocking (a single-task caller that must also service other work).
    bool runOnce(int max_wait_ms) {
        drainTasks();
        if (!running_) {
            return false;  // a task (stop) cleared running_
        }
        // Fire the earliest due timer, else note the next due time. Ordered map,
        // linear due-scan (n small).
        const auto now = std::chrono::steady_clock::now();
        bool have_due = false;
        std::uint64_t due_id = 0;
        std::optional<std::chrono::steady_clock::time_point> earliest;
        for (const auto &kv : timers_) {
            if (kv.second.next <= now) {
                due_id = kv.first;
                have_due = true;
                break;
            }
            if (!earliest || kv.second.next < *earliest) {
                earliest = kv.second.next;
            }
        }
        if (have_due) {
            const auto it = timers_.find(due_id);
            std::function<void()> fn = it->second.fn;  // copy: a periodic timer re-fires
            if (it->second.periodic) {
                it->second.next = now + it->second.period;
            } else {
                timers_.erase(it);
            }
            fn();
            return true;  // re-scan: the handler may have armed/cancelled timers
        }
        // Build the poll set: the wake fd plus every watched fd.
        poll_fds_.clear();
        if (waker_) {
            poll_fds_.push_back(waker_->pollFd());
        }
        for (const auto &kv : watches_) {
            poll_fds_.push_back(kv.second.fd);
        }
        int timeout_ms = max_wait_ms;
        if (earliest) {
            const auto d =
                std::chrono::duration_cast<std::chrono::milliseconds>(*earliest - now).count();
            const int until = (d < 0) ? 0 : static_cast<int>(d);
            if (until < timeout_ms) {
                timeout_ms = until;
            }
        }
        mux_.poll(poll_fds_.data(), poll_fds_.size(), timeout_ms, readable_);
        // Collect the watch IDs to fire, then dispatch by re-looking-up each — a
        // handler may unwatch another watch readable this round, so membership is
        // re-checked at fire time. The wake fd is drained, never dispatched.
        fire_.clear();
        for (const int fd : readable_) {
            if (waker_ && fd == waker_->pollFd()) {
                waker_->drain();
                continue;
            }
            for (const auto &kv : watches_) {
                if (kv.second.fd == fd) {
                    fire_.push_back(kv.first);
                }
            }
        }
        for (const std::uint64_t id : fire_) {
            const auto it = watches_.find(id);
            if (it != watches_.end()) {  // still watched (a prior handler may have removed it)
                std::function<void()> fn = it->second.fn;  // copy: a handler may remove its own
                fn();                                       // watch, freeing the stored function
            }
        }
        return running_;
    }

private:
    IoMultiplexer &mux_;
#ifndef TC8_REACTOR_SINGLE_THREAD
    std::thread thread_;
    std::thread::id thread_id_;
    std::mutex mu_;                 // guards tasks_ only (the cross-thread queue)
#endif
    bool running_ = false;          // loop state after start() / open()
    std::deque<std::function<void()>> tasks_;
    std::unique_ptr<Waker> waker_;  // cross-thread wake for poll(); null if unsupported

    // Loop-thread-only state (no lock): timers, fd watches, and the poll scratch
    // buffers reused each iteration.
    std::map<std::uint64_t, Timer> timers_;
    std::uint64_t next_timer_id_ = 1;
    std::map<std::uint64_t, Watch> watches_;
    std::uint64_t next_watch_id_ = 1;
    std::vector<int> poll_fds_;
    std::vector<int> readable_;
    std::vector<std::uint64_t> fire_;  // watch ids to dispatch this round
};

}  // namespace tc8::testability
