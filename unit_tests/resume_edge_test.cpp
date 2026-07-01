// Unit cover for ResumeEdge — the warm-re-offer edge detector dut_main uses to fire
// onReactivate once per observed advance of ServerRole's monotonic resume counter.
// This is the fallible marshalling step (seed / no-fire-when-equal / fire-once-on-
// advance / coalesce-a-burst / wrap-safe); the same "extract and unit-test the
// fallible step" discipline the demo test applies to payloadBytes(). The detached-
// thread increment and the main-loop dispatch are trivial call sites around this
// logic; this locks the logic itself.

#include <cstdint>

#include <gtest/gtest.h>

#include "resume_edge.h"

TEST(ResumeEdge, DoesNotFireWhenCounterUnchanged) {
    tc8::dut::ResumeEdge edge{0};
    EXPECT_FALSE(edge.advanced(0));
    EXPECT_FALSE(edge.advanced(0));
}

TEST(ResumeEdge, FiresOncePerObservedAdvance) {
    tc8::dut::ResumeEdge edge{0};
    EXPECT_TRUE(edge.advanced(1));   // first re-offer
    EXPECT_FALSE(edge.advanced(1));  // same value: no re-fire
    EXPECT_TRUE(edge.advanced(2));   // next re-offer
}

TEST(ResumeEdge, CoalescesABurstIntoOneFire) {
    // Two re-offers seen in one poll window (counter jumps +2) fire onReactivate ONCE
    // — the documented level-triggered contract for the idempotent re-anchor hook.
    tc8::dut::ResumeEdge edge{0};
    EXPECT_TRUE(edge.advanced(2));
    EXPECT_FALSE(edge.advanced(2));
}

TEST(ResumeEdge, SeedSuppressesInitialActivation) {
    // Seeding with the counter's loop-entry value means the initial activation is not
    // mistaken for a re-activation: the first poll at the seed value does not fire.
    tc8::dut::ResumeEdge edge{5};
    EXPECT_FALSE(edge.advanced(5));
    EXPECT_TRUE(edge.advanced(6));
}

TEST(ResumeEdge, WrapStillFires) {
    // The counter is uint32_t; a 2^32 wrap must still register as an advance (!=, not
    // >), so onReactivate is never silently stalled after ~4e9 re-offers.
    tc8::dut::ResumeEdge edge{0xFFFFFFFFu};
    EXPECT_TRUE(edge.advanced(0x00000000u));
}
