#!/usr/bin/env bash
# How many compile jobs a build may run at once on this machine, printed on stdout.
#
# The bound is the memory the run was granted divided by what one job peaks at
# (`peak_gb_per_task` in bx.toml, the one place that figure lives), capped by the cores
# it was granted. At least 1: a machine that cannot afford one job at a time is refused
# at placement (`min_ram_gb`), not here.
#
# bx exports the grant as BX_GRANT_CORES and BX_GRANT_MEM_MB. Outside bx neither is set,
# and the machine's cores and available memory stand in for them.
#
# Why the build asks for this instead of leaving the count to bx's jobserver: measured
# 2026-10-28 on a 15 GB build machine, a run bx gave one jobserver slot was ended by its
# 14.2 GB ceiling (33 OOM kills, peak 14.3 GB) compiling the case registrar units, while the
# same tree built with a single job peaked at 4.5 GB. A count computed from the grant is
# the bound that held.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
per_task_gb=$(sed -n 's/^peak_gb_per_task[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$root/bx.toml" | head -n 1)
: "${per_task_gb:?peak_gb_per_task not found in bx.toml}"

cores=${BX_GRANT_CORES:-$(nproc)}
mem_mb=${BX_GRANT_MEM_MB:-$(awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo)}

jobs=$(( mem_mb / (per_task_gb * 1024) ))
if [ "$jobs" -gt "$cores" ]; then jobs=$cores; fi
if [ "$jobs" -lt 1 ]; then jobs=1; fi
echo "$jobs"
