#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include <poll.h>

#include "tc8/pollable_service.h"

#include "ets_io_host.h"

namespace tc8::dut {

// Owns the pollable receivers an extension adopts and drains them on the DUT main
// loop's single thread — the DUT-side counterpart of the tester capture loop's
// drain set (sce_integration/test_runner.h). dut_main holds one for the whole run
// and calls drainReady() once per loop pass; the services live until the host is
// destroyed (the DUT hard-exits via std::_Exit, which reclaims the fds at process
// exit and skips these dtors, exactly as it does the vsomeip facades' — so the
// "owned for the run" lifetime is what matters, not the dtor).
//
// Single-thread model: adoptPollable() and drainReady() both run on the main-loop
// thread, so a service's onReadable() shares that thread with onTick() — no worker
// thread, exactly as on the tester side. An extension that also serves the drained
// data from a vsomeip handler thread owns that cross-thread synchronization itself;
// the host imposes none and assumes none.
class PollableHost final : public IEtsIoHost {
public:
    void adoptPollable(std::unique_ptr<tc8::IPollableService> service) override {
        services_.push_back(std::move(service));
    }

    // Poll every adopted service's fd for up to timeout_ms and drain the ready ones
    // via onReadable(). Returns as soon as poll() wakes — promptly on data, or after
    // the timeout. With no adopted fd this is a plain sleep(timeout_ms), so a DUT
    // that adopts nothing keeps its prior loop cadence exactly.
    void drainReady(int timeout_ms) {
        std::vector<pollfd> pfds;
        std::vector<tc8::IPollableService*> ready;  // parallel to pfds
        pfds.reserve(services_.size());
        ready.reserve(services_.size());
        for (const auto& service : services_) {
            const int fd = service->pollFd();
            if (fd < 0) {
                continue;  // a service that failed to acquire an fd is owned, not polled
            }
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = static_cast<short>(POLLIN);
            pfds.push_back(pfd);
            ready.push_back(service.get());
        }
        if (pfds.empty()) {
            if (timeout_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
            }
            return;
        }
        const int n = ::poll(pfds.data(), static_cast<nfds_t>(pfds.size()), timeout_ms);
        if (n <= 0) {
            return;  // timeout (0) or interrupted/error (<0) — the next pass retries
        }
        std::vector<tc8::IPollableService*> dead;
        for (std::size_t i = 0; i < pfds.size(); ++i) {
            const short re = pfds[i].revents;
            if (re == 0) {
                continue;
            }
            if (re & (POLLIN | POLLERR)) {
                // Data to drain, or a datagram async error the recv() retrieves and
                // clears. onReadable() must drain to EWOULDBLOCK (see IPollableService).
                ready[i]->onReadable();
            }
            if (re & (POLLHUP | POLLNVAL)) {
                // Terminal: a non-blocking read cannot clear POLLHUP (peer hung up)
                // or POLLNVAL (the service's fd is closed/invalid), so poll() would
                // report it on every pass — stop polling this service to avoid a
                // 100% busy-spin. The seam owner re-adopts a fresh receiver if its
                // endpoint reopens.
                dead.push_back(ready[i]);
            }
        }
        if (!dead.empty()) {
            services_.erase(
                std::remove_if(services_.begin(), services_.end(),
                               [&dead](const std::unique_ptr<tc8::IPollableService>& s) {
                                   return std::find(dead.begin(), dead.end(), s.get()) !=
                                          dead.end();
                               }),
                services_.end());
        }
    }

    // The number of adopted services still being polled (a dead-fd service is
    // dropped on POLLHUP/POLLNVAL). For introspection and tests.
    std::size_t adoptedCount() const { return services_.size(); }

private:
    std::vector<std::unique_ptr<tc8::IPollableService>> services_;
};

}  // namespace tc8::dut
