#pragma once

namespace tc8::capture {
class PcapSource;
}

namespace tc8::cli {

// RAII guard that installs SIGINT/SIGTERM handlers which call
// PcapSource::breakLoop() on the bound source and set a global stop flag.
// Restores the default handlers and clears the bound source on destruction.
// One guard at a time — subsequent guards overwrite the previous binding.
class SignalGuard {
public:
    explicit SignalGuard(capture::PcapSource &src);
    ~SignalGuard();

    SignalGuard(const SignalGuard &) = delete;
    SignalGuard &operator=(const SignalGuard &) = delete;

    // Observable from anywhere (e.g. command loops); cleared each time a
    // new guard is constructed.
    static bool stopRequested();
};

}  // namespace tc8::cli
