# DUT vsomeip flavor (CASE_VSOMEIP_VARIANT) — rationale sidecar

The `vsomeip_cfg` / `vsomeip_env` axis of `docs/spec/inventory_overrides.json`
(schema 8, the seventh axis) names, per case, the DUT-launch flavor a SOME/IP
case needs: an alternate vsomeip config (a sibling of the base
`dut/dut_service/vsomeip.json`) and/or `TC8_DUT_*` env the DUT app
(`dut/dut_service`) reads. The harness NEVER launches the DUT, so it does not
apply these — it only parses and EXPOSES them via `--list-vsomeip-variants` for
whichever driver spawns the DUT (single-pc / ssh-remote), exactly as it exposes
`--list-neg-rows` for a driver-applied negative row. Values live in the JSON;
this doc is the `_ref` rationale, so the value and its justification stay
separated (the JSON's own convention).

## Flavors

| flavor | `vsomeip_cfg` | `vsomeip_env` | what the DUT does |
|---|---|---|---|
| multi-instance | `vsomeip-multi-instance.json` | `TC8_DUT_INSTANCE_2=1` | offers the same service as a 2nd instance |
| multi-service | `vsomeip-multi-service.json` | `TC8_DUT_SERVICE_2=1` | offers a 2nd, distinct service |
| multi-service-shared-port | `vsomeip-multi-service-shared-port.json` | `TC8_DUT_SERVICE_2=1` | two services on one port |
| client-mode | (base cfg) | `TC8_DUT_CLIENT_MODE=1` | acts as a SOME/IP client |
| client-mode-udp | (base cfg) | `TC8_DUT_CLIENT_MODE=1`, `TC8_DUT_CLIENT_MODE_UDP=1` | client subscribe over UDP |

The server-side flavors (SOMEIPSRV multi-instance / multi-service) change only
which config the DUT offers; the client-mode flavors keep the base config and
flip DUT-app behavior via env.

## §5.1.5 multi-instance / multi-service plumbing + the SD_MESSAGE_17/_18 caveat

SD_MESSAGE_01/_02 + RPC_14/_17 require Number Of Instances = 2 for SERVICE-ID-1;
RPC_01/_02/_13 require a second SERVICE-ID-2. Each variant ships its own
`vsomeip-*.json` (the `services[]` differs) and is gated at runtime by the
`TC8_DUT_*` env `dut_main.cpp` inspects. The single-instance baseline (every
other §5.1.5 case) is untouched.

CRITICAL: SD_MESSAGE_17/_18 use `cfg.someip.instance_id + 1` and
`cfg.someip.major_version + 1` as UNKNOWN-* sentinels; activating instance
`0x0002` in the multi-instance variant would convert vsomeip's Nack into an Ack
and break those legacy assertions. Adding a §5.1.5 case to the multi-instance
flavor MUST be paired with a check that its cond does not depend on
`(instance_id + 1)` or `(major_version + 1)` being unknown.

## Client-mode rationale (§5.1.6 SOMEIP_ETS)

TC8 §5.1.6 SOMEIP_ETS_097 routes `clientServiceActivate` to the CommonAPI Proxy
spawn path (ets3 `ClientTarget`) instead of the raw-UDP runner. Env-gated so the
existing client-mode cases keep their wire shape. §5.1.6 SOMEIP_ETS_084 and
§5.1.6 SOMEIP_ETS_081 reuse ETS_097's CommonAPI Proxy path — observation of the
DUT-emitted Subscribe / StopSubscribe (084) and the reboot OfferService verdict
(081) both depend on the proxy spawn on activate / unsubscribe on deactivate.

§5.1.6 SOMEIP_ETS_082 selects the UDP-unreliable target event in `ets3.fdepl`
(eventgroup `0x000B`) so the DUT-emitted SubscribeEventgroup carries an IPv4
Endpoint Option with `l4proto = 0x11` (UDP); it implies `TC8_DUT_CLIENT_MODE=1`.
§5.1.6 SOMEIP_ETS_106 (`ClientServiceSubscribeEventgroup`) reuses the UDP
variant. §5.1.6 SOMEIP_ETS_103 / _104 / _105 (`GetLastValueOfEvent*`) require
Client Mode active so `clientServiceSubscribeEventgroup` wires up the proxy
subscribe path (without it the Method `0x32` dispatch is a no-op).
