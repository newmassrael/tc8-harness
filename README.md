# `pcap-data` branch

This branch holds per-case packet captures decoded to JSON for the harness
site at https://newmassrael.github.io/tc8-harness/. It is **not** part of
the codebase history — `main` does not track these files.

Layout mirrors the site's expected path so a single copy step in CI
(`actions/checkout` with `ref: pcap-data` + `path: .pcap` + `cp -r`)
overlays the captures onto the main checkout before `astro build`:

    site/src/data/pcap/<CASE_ID>.json   # one record per case

Each JSON conforms to the `PacketCapture` shape defined in
`site/src/lib/types.ts` (idx, ts_us, ts_delta_us, direction, src/dst
mac+ip, protocol, summary, fields).

## Update flow

1. Self-hosted runner (label `[self-hosted, netns]`) executes
   `dut/env/smoke-test.sh --log-dir <tmp>` per case.
2. `site/scripts/decode_pcap.py` (lives on `main`) decodes each pcap to
   the JSON shape and writes here.
3. Sanitization (`site/scripts/sanitize_pcap.py`) runs before commit —
   public IPs / non-fixture MACs fail the workflow.
4. Resulting commit on `pcap-data` triggers nothing (path filter on
   `site.yml` is scoped to `main`); the next `main` push (or a manual
   `workflow_dispatch`) picks up the latest captures.

## Why orphan

Keeps `git log main` free of refresh churn (capture timestamps change
per run). Each refresh = one commit on `pcap-data` only.
