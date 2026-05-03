#include "cli/replay_command.h"

#include <cstdio>
#include <utility>

#include "capture/bpf_filter.h"
#include "capture/pcap_source.h"
#include "cli/capture_driver.h"

namespace tc8::cli {

ReplayCommand::ReplayCommand(CLI::App &app) {
    sub_ = app.add_subcommand("replay", "Replay a pcap file");
    sub_->add_option("file", pcap_file_, "Path to .pcap or .pcapng file")->required()->check(CLI::ExistingFile);
}

int ReplayCommand::run(std::optional<std::string> bpf_override) {
    const std::string bpf = bpf_override.has_value() ? std::move(*bpf_override) : capture::bpf::someip();
    std::printf("source   : replay (%s)\n", pcap_file_.c_str());
    return runCapture(capture::PcapSource::openOffline(pcap_file_), bpf);
}

}  // namespace tc8::cli
