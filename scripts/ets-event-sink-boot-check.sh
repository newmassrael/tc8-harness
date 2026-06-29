#!/bin/sh
# Boot the real tc8-dut briefly and assert the ETS event-sink seam resolved the
# CommonAPI-owned vsomeip application (makeEtsEventSink, dut/dut_service/
# ets_event_sink.cpp). The seam returns a sink whether or not retrieval succeeds,
# and the public conformance suite's default IEtsExtension never exercises the
# sink, so the ONLY signal that retrieval silently failed is the DUT's
# "OEM event surface disabled" stderr line. This guards against a regression
# (e.g. a CommonAPI/vsomeip application-keying change) that would re-disable every
# OEM event surface without any conformance case noticing — exactly the class of
# bug that motivated the seam fix.
set -u

DUT_BIN=${1:?usage: ets-event-sink-boot-check.sh <tc8-dut-binary>}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
log="$work/dut.log"

# The DUT runs until signalled; timeout SIGTERMs it once it has registered
# (expected, exit 124). The verdict is read from the log, not the exit code:
# registration and the seam log line are emitted at startup, before any SD
# networking, so this is robust without netns / multicast.
timeout 5 env \
    COMMONAPI_CONFIG="$ROOT/dut/dut_service/commonapi.ini" \
    VSOMEIP_CONFIGURATION="$ROOT/dut/dut_service/vsomeip.json" \
    VSOMEIP_APPLICATION_NAME=tc8-dut \
    VSOMEIP_BASE_PATH="$work" \
    "$DUT_BIN" >"$log" 2>&1

if ! grep -q "registered (domain=" "$log"; then
    echo "FAIL: tc8-dut did not register its ETS service" >&2
    tail -20 "$log" >&2
    exit 1
fi
if grep -q "OEM event surface disabled" "$log"; then
    echo "FAIL: ETS event-sink could not resolve the CommonAPI application" >&2
    echo "      (regression in makeEtsEventSink / CommonAPI app keying)" >&2
    exit 1
fi

echo "PASS: ETS event-sink resolved the CommonAPI application"
exit 0
