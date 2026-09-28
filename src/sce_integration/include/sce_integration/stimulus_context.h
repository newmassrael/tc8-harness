#pragma once

#include <string_view>

namespace tc8::sce {

class IDutControl;
class IStimulusScheduler;
class IBackgroundServiceOwner;
class IStimulusObserver;

// Everything a case's stimulus can act through, in one argument:
//
//   static void stimulus(Captured&, const ::tc8::TestConfig&, StimulusContext&);
//
// It is the only stimulus signature. It replaced six overloads told apart by
// arity and by the type of their fourth parameter, two of which were only unions
// of two others (docs/tech-debt.md TD-62); a seventh capability would have
// doubled the set. With one argument a new capability is a new member, and a
// case asks for what it uses by using it.
//
// Every member is a borrowed reference that is valid for the duration of the
// `stimulus()` call. The scheduler and the service owner may be handed work that
// outlives it (that is what they are for); the observer may not
// (IStimulusObserver::awaitObservation).
struct StimulusContext {
    // The capture interface; stimulus emitted on it is seen by the capture.
    std::string_view iface;
    // The DUT-control backend selected by --dut-control.
    IDutControl &dut;
    // Actions to fire from the capture loop after the listen window opens.
    IStimulusScheduler &scheduler;
    // Run-scoped background services the runner owns across the capture window.
    IBackgroundServiceOwner &services;
    // Waits on the case's own capture while the stimulus runs.
    IStimulusObserver &observer;
};

}  // namespace tc8::sce
