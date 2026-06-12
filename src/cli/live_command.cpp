#include "cli/live_command.h"

#include <cstdio>
#include <utility>

#include "capture/bpf_filter.h"
#include "capture/pcap_source.h"
#include "cli/capture_driver.h"

namespace tc8::cli {

LiveCommand::LiveCommand(CLI::App &app) {
    sub_ = app.add_subcommand("live", "Live capture from a NIC");
    sub_->add_option("-i,--interface", iface_, "NIC name, e.g. eth0")->required();
    sub_->add_option("-t,--read-timeout", read_timeout_ms_, "Kernel read timeout in milliseconds")
        ->capture_default_str();
}

int LiveCommand::run(std::optional<std::string> bpf_override) {
    const std::string bpf = bpf_override.has_value()
        ? std::move(*bpf_override)
        : capture::bpf::vlanAware(capture::bpf::someip());
    std::printf("source   : live (%s)\n", iface_.c_str());
    return runCapture(capture::PcapSource::openLive(iface_, /*snaplen=*/65535, read_timeout_ms_), bpf);
}

}  // namespace tc8::cli
