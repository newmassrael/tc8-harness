#pragma once

#include <memory>
#include <string>

namespace tc8::capture {
class PcapSource;
}

namespace tc8::cli {

// Shared driver for the `live` and `replay` subcommands: applies the BPF,
// installs the signal guard, and runs the dispatch loop printing each
// SOME/IP message until EOF, a signal, or an error.
int runCapture(std::unique_ptr<capture::PcapSource> src, const std::string &bpf);

}  // namespace tc8::cli
