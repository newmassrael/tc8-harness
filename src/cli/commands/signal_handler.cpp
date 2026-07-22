#include "cli/signal_handler.h"

#include <atomic>
#include <csignal>

#include "capture/pcap_source.h"

namespace tc8::cli {

namespace {

capture::PcapSource *g_active_source = nullptr;
std::atomic<bool> g_stop{false};

void onSignal(int /*signum*/) {
    g_stop.store(true, std::memory_order_relaxed);
    if (g_active_source != nullptr) {
        g_active_source->breakLoop();
    }
}

}  // namespace

SignalGuard::SignalGuard(capture::PcapSource &src) {
    g_stop.store(false, std::memory_order_relaxed);
    g_active_source = &src;
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
}

SignalGuard::~SignalGuard() {
    std::signal(SIGINT, SIG_DFL);
    std::signal(SIGTERM, SIG_DFL);
    g_active_source = nullptr;
}

bool SignalGuard::stopRequested() {
    return g_stop.load(std::memory_order_relaxed);
}

}  // namespace tc8::cli
