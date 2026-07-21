#pragma once

#include <optional>
#include <string>

#include <CLI/CLI.hpp>

namespace tc8::cli {

class LiveCommand {
public:
    explicit LiveCommand(CLI::App &app);

    bool parsed() const {
        return sub_->parsed();
    }

    int run(std::optional<std::string> bpf_override);

private:
    CLI::App *sub_ = nullptr;
    std::string iface_;
    int read_timeout_ms_ = 100;
};

}  // namespace tc8::cli
