#pragma once

#include <chrono>
#include <cstdint>

#include "tc8/test_defaults.h"

namespace tc8 {

// The tester's own configuration parameters for a run (ISO/IEC 9646 IXIT): the
// values the specification leaves to whoever runs the suite. Separate from the
// expectation DTOs because nothing here is guard-compared; these decide which
// observations are valid, not what a frame must carry.
struct IxitConfig {
    // TC8 <ParamListenTime>, in milliseconds (tc8::defaults::kParamListenTime).
    // A final that declares `"bound":"ParamListenTime"` judges its absence
    // against this: a window shorter than it does not show the DUT stayed silent
    // for as long as it was allowed to answer.
    std::uint32_t param_listen_time_ms = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(defaults::kParamListenTime).count());
};

}  // namespace tc8
