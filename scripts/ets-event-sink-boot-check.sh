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
if grep -q "OEM client surface disabled" "$log"; then
    echo "FAIL: ETS client-control could not resolve the CommonAPI application" >&2
    echo "      (regression in makeEtsClientControl / CommonAPI app keying)" >&2
    exit 1
fi

# Client-only mode (TC8_DUT_CLIENT_ONLY=1, the client-role CLT topology): the DUT must
# NOT offer the primary ETS service, yet the seam must STILL resolve the vsomeip
# application — created here DIRECTLY (create_application under the default
# connection id + init + threaded start, offering and finding nothing) instead of
# via registerService or a proxy. Guards the client-only design: a regression that
# re-offered the service (local subscribe satisfaction, no wire SubscribeEventgroup),
# failed to create the app, or reverted to the boot-Find proxy vehicle would surface
# here. This is a no-netns log check, so it does NOT observe SD egress on the wire —
# the boot-Find guarantee is enforced STRUCTURALLY (ClientOnlyApplication issues no
# request_service) and asserted here only via the proxy-vehicle marker below.
# Own base-path so it never collides with the server-mode app above.
clog="$work/dut-client-only.log"
mkdir -p "$work/co"
timeout 5 env \
    TC8_DUT_CLIENT_ONLY=1 \
    COMMONAPI_CONFIG="$ROOT/dut/dut_service/commonapi.ini" \
    VSOMEIP_CONFIGURATION="$ROOT/dut/dut_service/vsomeip.json" \
    VSOMEIP_APPLICATION_NAME=tc8-dut \
    VSOMEIP_BASE_PATH="$work/co" \
    "$DUT_BIN" >"$clog" 2>&1

if ! grep -q "client-only mode" "$clog"; then
    echo "FAIL: TC8_DUT_CLIENT_ONLY did not engage client-only mode" >&2
    tail -20 "$clog" >&2
    exit 1
fi
if ! grep -q "application created directly" "$clog"; then
    echo "FAIL: client-only vsomeip application was not created directly" >&2
    tail -20 "$clog" >&2
    exit 1
fi
# Regression guard for the known boot-Find vehicle: the only thing that
# request_service()s the ClientTarget at boot is building its CommonAPI proxy, which
# prints this marker (client_mode_proxy.cpp). Its ABSENCE proves that vehicle was not
# rebuilt. It does NOT prove the absence of every conceivable boot Find (a stray
# request_service elsewhere would pass) — that is a structural property of
# ClientOnlyApplication, not something this log check can observe.
if grep -q "ClientTarget proxy built" "$clog"; then
    echo "FAIL: client-only DUT rebuilt the boot-Find ClientTarget proxy vehicle" >&2
    echo "      (its request_service would emit a boot FindService)" >&2
    exit 1
fi
if grep -q "registered (domain=" "$clog"; then
    echo "FAIL: client-only DUT still offered the primary ETS service" >&2
    echo "      (would satisfy the OEM client subscribe locally — no wire frame)" >&2
    exit 1
fi
# Both seams share one acquireCommonApiApplication, so a keying regression disables
# them together — assert both surfaces resolve (symmetric with the server block).
if grep -q "OEM event surface disabled" "$clog"; then
    echo "FAIL: client-only event-sink could not resolve the directly-created app" >&2
    exit 1
fi
if grep -q "OEM client surface disabled" "$clog"; then
    echo "FAIL: client-only client-control could not resolve the directly-created app" >&2
    exit 1
fi

echo "PASS: seam resolves in server mode AND client-only mode (no primary offer)"
exit 0
