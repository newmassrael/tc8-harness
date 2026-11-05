#pragma once

#include <string>

#include <CLI/CLI.hpp>

namespace tc8::cli {

// `tc8-harness dissect <pcap>`: replay a saved capture through the packet pipeline and
// print every event it hands a case, one line each with every field (payloads in hex),
// then the run's dissection accounting.
//
// What a case is graded on is exactly this event stream, so this is the view to read
// when a verdict and a pcap disagree, and the instrument that proves two builds of the
// dissector equivalent: their output on the same captures is compared line for line.
class DissectCommand {
public:
    explicit DissectCommand(CLI::App &app);

    bool parsed() const { return sub_->parsed(); }
    int run();

private:
    CLI::App *sub_ = nullptr;
    std::string pcap_file_;
    std::string dut_mac_;
};

}  // namespace tc8::cli
