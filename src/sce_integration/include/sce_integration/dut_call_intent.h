#pragma once

#include <cstdint>

namespace tc8::sce {

// Why a case makes a DUT-control call, which decides what an unsuccessful answer
// means for the run (recording_dut_control.h):
//
//   kStimulus  the default: the case needs the DUT to do it before it can grade
//              anything after. An answer short of done is an unperformed stimulus.
//   kGraded    the answer IS what the case grades (RFC 793 3.9: CLOSE on a
//              connection that does not exist must be refused). A refusal is the
//              DUT's answer, an observation; only no answer at all is recorded.
//              It applies to a call that returns a DutCallOutcome; a bool cannot
//              tell a refusal from a lost request, so it is recorded as kStimulus.
//   kCleanup   releasing what the case set up, after everything it grades: the
//              answer bears on no verdict, so nothing is recorded.
enum class DutCallIntent : std::uint8_t { kStimulus, kGraded, kCleanup };

// The intent of the DUT-control calls made on this thread while it is alive;
// nested scopes restore the outer one on exit. Per thread, like TxSpecStep, since a
// call made on the capture thread by a scheduled step is not the stimulus's.
class DutCallIntentScope {
public:
    explicit DutCallIntentScope(DutCallIntent intent) : previous_(slot()) { slot() = intent; }
    ~DutCallIntentScope() { slot() = previous_; }
    DutCallIntentScope(const DutCallIntentScope &) = delete;
    DutCallIntentScope &operator=(const DutCallIntentScope &) = delete;

    static DutCallIntent current() { return slot(); }

private:
    static DutCallIntent &slot() {
        thread_local DutCallIntent intent = DutCallIntent::kStimulus;
        return intent;
    }

    DutCallIntent previous_;
};

}  // namespace tc8::sce
