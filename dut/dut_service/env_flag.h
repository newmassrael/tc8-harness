#pragma once

#include <cstdlib>

namespace tc8::dut {

// True when environment variable `name` is set to a non-empty value other than
// "0". The single source of truth for the DUT's boolean env gates
// (TC8_DUT_CLIENT_ONLY, TC8_DUT_INSTANCE_2, TC8_DUT_SERVICE_2): dut_main reads
// the topology gate, ServerRole reads the per-axis gates, both through this.
inline bool envFlagOn(const char* name) {
    const char* v = std::getenv(name);
    return v != nullptr && v[0] != '\0' && v[0] != '0';
}

}  // namespace tc8::dut
