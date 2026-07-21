#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include <CLI/CLI.hpp>

namespace tc8::cli {

class ReplayCommand {
public:
    explicit ReplayCommand(CLI::App &app);

    bool parsed() const {
        return sub_->parsed();
    }

    int run(std::optional<std::string> bpf_override);

private:
    CLI::App *sub_ = nullptr;
    std::filesystem::path pcap_file_;
};

}  // namespace tc8::cli
