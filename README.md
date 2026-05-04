# tc8-harness
W3C SCXML-based conformance test harness for automotive Ethernet ECUs (OA TC8 Layer 3-7)

[![build-test](https://github.com/newmassrael/tc8-harness/actions/workflows/build-test.yml/badge.svg)](https://github.com/newmassrael/tc8-harness/actions/workflows/build-test.yml) [![smoke-test](https://github.com/newmassrael/tc8-harness/actions/workflows/smoke-test.yml/badge.svg)](https://github.com/newmassrael/tc8-harness/actions/workflows/smoke-test.yml)

## Scope

`tc8-harness` verifies that a vsomeip-based DUT (ECU) conforms to OA
TC8 v3.0 Layer 3-7 — IPv4, ARP, ICMPv4, UDP, DHCPv4 client, link-local
autoconf, TCP, SOME/IP, SOME/IP-SD. The current corpus is **543 / 543
active cases** at 100 % spec coverage.

**Non-goals** (out of scope by design):

- Submission for OA's official TC8 certification (Vector CANoe / TTCN-3
  only — this is a pre-qualification + CI-regression tool, not a
  certification package).
- Layers 1-2 (PHY, IEEE 802.1 Qav/Qbv TSN).
- EMC / environmental testing.
- Specs other than OA TC8 v3.0, OEM-custom assertions.

## Architecture

```
                tester host (Linux)                        DUT
  ┌──────────────────────────────────────────┐         ┌──────────┐
  │  capture: libpcap (BPF in kernel)        │         │ vsomeip  │
  │     │                                    │         │ ECU fw   │
  │     ▼                                    │◀── eth ▶│          │
  │  dissect: libtins + direct SOME/IP        │         └──────────┘
  │     │                                    │
  │     ▼                                    │
  │  per-case TestCaseTraits<SM>             │
  │     │  stimulus(Captured&, cfg, iface)   │
  │     │  verdictFor(State) → pass/fail/…   │
  │     ▼                                    │
  │  W3C SCXML interpreter (embedded SCE)    │
  │     • cpp:-prefix conds + donedata       │
  │     • <sce:use template> reuse           │
  │     ▼                                    │
  │  upper-tester JSON-line over TCP ─────────┼────────▶│ tc8-dut
  └──────────────────────────────────────────┘         │ firmware
                                                       └──────────┘
```

Each TC8 case lives at `tests/<case_id>/<case_id>.scxml` plus a
matching `src/sce_integration/cases/<case_id>.h` that specialises
`TestCaseTraits<SM>`. Adding a case = those two files. CMake auto-wires
the rest (codegen, registration, BPF group, build dependency on
`tests/_templates/*.sce-template.xml` fragments via SCE's
`--write-deps`).

### Key technology choices

| Layer | Choice | Why |
|-------|--------|-----|
| Capture | **libpcap** (libtins thin wrapper) | mature, portable, in-kernel BPF; hardware timestamps not needed at L3-7. |
| SOME/IP dissect | **direct C++ parser** | Wireshark dissector is GPL → incompatible with our Apache-2.0 + SCE LGPL-with-linking-exception stack. Header is small (50-100 LoC). |
| SOME/IP payload | **CommonAPI generated InputStream** | reuses TLV/endian/alignment baked into `.fidl`/`.fdepl`-driven proxy code. |
| Stimulus | **vsomeip C++ API directly** | mesh abstraction adds friction in test context; vsomeip is the canonical client. |
| Orchestration | **W3C SCXML via SCE static AOT** | per-case state machine in standard format, AOT-compiled to C++; mesh-independent. |
| Test event injection | `engine.raiseExternalEvent(...)` | standard SCE entry point. |
| Verdict reporting | `<final>` state + `<donedata>` JSON | W3C-standard, language-agnostic; collected via SCE's `DoneData::getContent()`. |

### Test case shape

Happy path:

```xml
<scxml xmlns="http://www.w3.org/2005/07/scxml"
       xmlns:cpp="urn:sce:cpp" version="1.0" initial="setup">

  <state id="setup">
    <onentry><send event="stimulus.fire"/></onentry>
    <transition event="stimulus.fire" target="waiting"/>
  </state>

  <state id="waiting">
    <onentry><send event="deadline_exceeded" delay="50ms"/></onentry>
    <transition event="captured.response" cond="cpp:ev.field_x == 42" target="pass"/>
    <transition event="deadline_exceeded" target="fail_timeout"/>
    <transition event="captured.response" target="fail_field"/>
  </state>

  <final id="pass"><donedata><content>{"verdict":"pass"}</content></donedata></final>
  <final id="fail_timeout"><donedata><content>{"verdict":"fail","reason":"no_response_within_50ms"}</content></donedata></final>
  <final id="fail_field"><donedata><content>{"verdict":"fail","reason":"field_x_mismatch"}</content></donedata></final>
</scxml>
```

Timing assertions piggyback on transition races between the observed
event and a `<send delay="…ms"/>`-driven deadline event — W3C-standard,
no script-engine clock dependency.

## Development Setup

### Prerequisites

- C++17 toolchain (g++ 9+ or clang 12+)
- cmake 3.16+
- libpcap-dev, libtins-dev
- quilt (`sudo apt install quilt`) — drives the vsomeip patch series
- Boost (system / thread / filesystem / log) — vsomeip dependency
- python3 (spec inventory tooling)

### Bootstrap (fresh clone)

```sh
git clone --recursive <repo-url> tc8-harness
cd tc8-harness
sudo ./scripts/setup-vsomeip.sh        # quilt push -a → cmake build → install to /usr/local
cmake -B build -DTC8_SCE_FIND_PACKAGE=OFF
cmake --build build -j4
```

If the clone is non-recursive, populate the submodule first:

```sh
git submodule update --init --recursive
sudo ./scripts/setup-vsomeip.sh
```

`setup-vsomeip.sh` honours `VSOMEIP_INSTALL_PREFIX` (default `/usr/local`)
so CI can co-locate vsomeip with CommonAPI under `/opt/someip-stack`.

### Adding a vsomeip patch

The harness vendors vsomeip via `third_party/vsomeip/` (submodule pinned to
3.7.1) and overlays a quilt series at `patches/vsomeip/series`. To add a
patch:

```sh
cd third_party/vsomeip
export QUILT_PATCHES="$(realpath ../../patches/vsomeip)"
quilt new 0002-<short-name>.patch
quilt add <files-to-edit>
# … edit files …
quilt refresh
quilt header -e 0002-<short-name>.patch    # add Subject + body explaining why
cd ../..
sudo ./scripts/setup-vsomeip.sh             # re-pop, re-push, rebuild, reinstall
```

`patches/vsomeip/0001-relax-return-code-on-requests.patch` is the
reference for patch shape, ABI-preservation rules, and upstream-bug
narration. Keep patches surgical: gate by `MT_REQUEST` rather than
broaden whitelists, leave `MT_RESPONSE` validation intact, attach a
`Refs:` line to a tracking issue.

## CI

Two workflows under `.github/workflows/` cover orthogonal slices of the test
matrix:

| workflow                 | runner                  | scope                                                                                                  |
| ------------------------ | ----------------------- | ------------------------------------------------------------------------------------------------------ |
| `build-test.yml`         | `ubuntu-22.04` (hosted) | submodule init → `setup-vsomeip.sh` (patched) + CommonAPI → `cmake build` → `ctest` → `--list-cases --vs-spec` drift gate |
| `smoke-test.yml`         | self-hosted `[netns]`   | `setup-vsomeip.sh` (idempotent re-pop/push) → harness build → `dut/env/smoke-test.sh --workers 4` (positive + `--negative`) |

Both workflows pass `submodules: recursive` to `actions/checkout@v4` so
`third_party/vsomeip` is populated before any build step. The hosted
build caches `/opt/someip-stack` keyed by the patch series + submodule
SHA — changing `patches/vsomeip/*` invalidates the cache.

### Self-hosted runner (`[netns]` label)

The smoke suite drives veth-pair netns isolation per worker, which needs
root and `CAP_NET_ADMIN`/`CAP_NET_RAW`. GitHub-hosted runners cannot
provide that. Provision a self-hosted runner once per host:

```bash
# 1. install the actions runner under /opt/actions-runner (per-GitHub docs)
# 2. apply the [self-hosted, netns] labels at registration time
# 3. install build deps (cmake, build-essential, quilt, libpcap-dev,
#    libtins-dev, libboost-{system,thread,filesystem,log}-dev)
# 4. add a sudoers fragment so the runner can run smoke-test.sh and
#    setup-vsomeip.sh non-interactively (the latter's `sudo cmake
#    --install` runs as root-from-root, no extra entry needed):
sudo tee /etc/sudoers.d/tc8-runner <<'EOF'
%docker ALL=(root) NOPASSWD: /opt/actions-runner/_work/tc8-harness/tc8-harness/dut/env/smoke-test.sh
%docker ALL=(root) NOPASSWD: /opt/actions-runner/_work/tc8-harness/tc8-harness/scripts/setup-vsomeip.sh
EOF
# 5. `sudo systemctl enable --now actions.runner.<owner>-<repo>.<runner-name>.service`
```

The harness's spec-coverage gate (`--list-cases --vs-spec --strict`)
runs in `build-test.yml` and currently emits a non-zero exit for the
~235 §4.6 UDP / §5 SOMEIP cases queued for future sessions. The CI step
is wrapped in `continue-on-error: true` until the team flips the gate
hard. Wall-time-deferred cases (`TCP_RETRANSMISSION_TO_08/_09`) are
already filtered via `doc/spec/inventory_overrides.json`.

## License

`tc8-harness` is licensed under the [Apache License 2.0](LICENSE).

Third-party components ship under their own licenses, retained in tree:

| Component | Location | License |
| --------- | -------- | ------- |
| SCE (SCXML Core Engine) | `third_party/sce/` | LGPL-2.1+ WITH SCE-Linking-Exception OR SCE-Commercial (`third_party/sce/LICENSE*`) |
| pugixml (vendored via SCE) | `third_party/sce/third_party/pugixml/` | MIT (`LICENSE.md`) |
| nlohmann/json (vendored via SCE) | `third_party/sce/third_party/nlohmann_json/` | MIT (covered by `third_party/sce/LICENSE-THIRD-PARTY.md`) |
| CLI11 | `third_party/CLI11/` | BSD-3-Clause (`LICENSE`) |
| vsomeip (submodule) | `third_party/vsomeip/` | MPL-2.0 (`third_party/vsomeip/LICENSE`); harness patches under `patches/vsomeip/` retain MPL-2.0 inheritance |

Runtime dependencies (libpcap, libtins, Boost, CommonAPI) are linked
from the system or built from upstream sources by `scripts/setup-vsomeip.sh`
and the build-test workflow; consult those projects for their respective
licenses.
