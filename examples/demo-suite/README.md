# Demo suite — suite-producer proof

This directory is a minimal out-of-tree case catalog ("suite") wired through the
same injection points an OEM catalog uses. It exists to exercise and document the
**suite producer** end to end; it is not a conformance suite.

## What it proves

`someipsrv_options_01/` deliberately reuses the **in-tree** case id
`someipsrv_options_01` (`SOMEIPSRV_OPTIONS_01`) under the suite `demo`. Building
the harness with this suite injected forces every layer that keys on the case id
to stay `(suite, id)`-aware rather than colliding:

- **Configure-time discovery** (`CMakeLists.txt`) — the `tests/<id>/` collision
  guard fires only for the default suite, so a non-default suite may reuse the id.
- **SCE codegen** — the demo SM is emitted as
  `::SCE::Generated::demo::someipsrv_options_01` into `gen/demo/`, distinct from
  the in-tree `::SCE::Generated::someipsrv_options_01` in `generated/`.
- **Registry** — `CaseRegistry` holds `tc8:SOMEIPSRV_OPTIONS_01` and
  `demo:SOMEIPSRV_OPTIONS_01` as distinct entries; `--list-cases` groups them
  under separate suite banners and `-c demo:SOMEIPSRV_OPTIONS_01` selects the
  demo one.

## Build it

```sh
cmake -S . -B build-demo \
  -DTC8_EXTRA_CASE_DIRS=$PWD/examples/demo-suite \
  -DTC8_EXTRA_CASE_SUITES=demo
cmake --build build-demo --target tc8-harness
./build-demo/tc8-harness --list-cases | grep -i options_01
#   tc8 suite : SOMEIPSRV_OPTIONS_01
#   demo suite: demo:SOMEIPSRV_OPTIONS_01
```

`TC8_EXTRA_CASE_DIRS` and `TC8_EXTRA_CASE_SUITES` are index-aligned `;`-lists:
the Nth directory's cases register under the Nth suite name (an empty or missing
entry defaults to the in-tree suite `tc8`).

## OEM authoring convention

A case in a non-default suite is authored exactly like an in-tree case — same
directory == lowercased `kCaseId`, same scxml `name=`, the literal spec id in
`kCaseId` — with **one** difference: it binds its generated state machine through
the three tokens the per-suite register stub stamps (see `tc8_add_case` in the
top-level `CMakeLists.txt`):

```cpp
#include TC8_CASE_SM_HEADER                       // "demo/<id>_sm.h"
using SM = ::SCE::Generated::TC8_CASE_SUITE_NS::<name>::<name>;
// kCaseId stays the literal spec id; CaseRegistrar reads TC8_CASE_SUITE.
```

Because the suite name lives only in those macros, the header text works under
any **non-default** suite — always via that suite's generated stub, which stamps
the macros (the header has no in-tree fallback and `#error`s if pulled in bare).
An in-tree case, by contrast, binds `::SCE::Generated::<name>` directly. See
`someipsrv_options_01/someipsrv_options_01.h`.
