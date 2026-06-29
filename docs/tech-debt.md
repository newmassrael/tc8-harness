# Tech-debt register

Known, accepted technical debt in tc8-harness. Each entry records WHAT the debt
is, WHY it exists, the RISK if left, the textbook FIX, and why it is DEFERRED.
This is a deliberate-deferral log, not a TODO list for unfinished features —
every item here is a working compromise with a documented escape path.

Entry format: a `## TD-NN` heading, then the fields below. Append new entries;
do not renumber. Reference an entry from code with a one-line pointer comment
(`see docs/tech-debt.md TD-NN`) at each coupled site so an editor of one site
discovers the others.

---

## TD-01 — SOME/IP-SD wire decode duplicated across C++ harness and Python site tooling

**Status:** OPEN (accepted, mitigated). **Logged:** 2026-06-29.

**What.** The byte-level decode of SOME/IP-SD entries/options is implemented
independently in three places that must agree bit-for-bit:

- C++ — `src/sce_integration/someip_captured.h` (`decodeSdEntry`,
  `parseSdHeaderInto`, `parseSdOptionsInto`). Authoritative: drives conformance
  verdicts.
- Python — `site/scripts/decode_pcap.py` (decodes a captured pcap to JSON).
- Python — `site/scripts/generate_messages.py` (a cond evaluator that synthesises
  the same field names so the documentation site can resolve SCXML guard
  expressions over a decoded message).

There is no shared source for the wire layout (field offsets/widths); each side
hand-mirrors it.

**Why it exists.** The harness is C++ (it runs the live verdicts); the rendered
documentation site (`https://newmassrael.github.io/tc8-harness/`) is a separate
Python toolchain that decodes the captured pcaps to JSON for display. The two
share no runtime and no code, so the wire layout is mirrored by hand.

**Risk if left.** A wire-layout change must be applied by hand in all three
places. A miss is a SILENT divergence, not a build break: `site/` is not in the
harness CMake build or ctest, and the Python decoders have no cross-check against
the C++ struct. The harness verdict stays correct (C++ is authoritative), but the
site preview renders stale/UNKNOWN field values for the affected guards.

**Surfaced by.** The `reserved_counter` -> `entry_reserved` + `counter` SD-entry
split (commit `7e7422a5`). The initial change updated only the C++ decoder; a
3-agent cold review caught that both Python mirrors still emitted the removed
`reserved_counter` and lacked `entry_reserved`. All three were then migrated
together — this debt entry records the structural coupling that made the miss
possible.

**Textbook fix (deferred — large).** Establish a single source of truth for the
SD wire layout, in rough order of effort:

1. A golden cross-language test: decode the same captured pcap through the C++
   decoder and `decode_pcap.py` and assert per-field equality. Catches drift
   without unifying the code — the cheapest real guard, addable independently.
2. A shared declarative schema (field name/offset/width per entry/option type)
   consumed by both the C++ decoder and the Python tooling (codegen or a runtime
   table), so the layout is written once.
3. Generate the Python decoders from the C++ field definitions (or vice versa).

**Why deferred.** Unifying a cross-language decoder is a substantial
architectural change; the present compromise is acceptable because (a) the
harness C++ remains authoritative for every conformance verdict, so there is no
verdict risk — only a site-preview-accuracy risk, and (b) the drift is mitigated
by the pointer comments at the three sites plus the standing 3-agent review on
wire-surface changes. Option 1 (the golden cross-language test) is the
recommended first step when this is picked up.
