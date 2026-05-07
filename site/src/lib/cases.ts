/**
 * Case manifest loaders. Astro reads every case JSON eagerly via Vite's
 * ``import.meta.glob`` so each detail page lands in the SSG bundle without
 * runtime fetches. ``allCases`` follows the spec-appearance order written
 * by ``build_manifest.py`` to ``index.json``.
 */

import type { CaseRecord, IndexFile } from './types';
import indexJson from '../data/index.json';

const caseModules = import.meta.glob<CaseRecord>('../data/cases/*.json', {
  eager: true,
  import: 'default',
});

const byId: Record<string, CaseRecord> = {};
for (const [path, mod] of Object.entries(caseModules)) {
  const id = path.split('/').pop()!.replace(/\.json$/, '');
  byId[id] = mod;
}

export const indexFile: IndexFile = indexJson as IndexFile;

export const allCases: CaseRecord[] = indexFile.cases
  .map((e) => byId[e.case_id])
  .filter((c): c is CaseRecord => Boolean(c));

export function getCase(id: string): CaseRecord | undefined {
  return byId[id.toUpperCase()];
}

/**
 * UI-facing status: maps the lifecycle status + last test outcome into a
 * single 4-way label rendered as a badge. ``deprecated`` always wins over
 * outcome (a removed case isn't "fail"); active cases without a recorded
 * outcome show ``untested`` so the user can tell the data is missing,
 * not green-by-default.
 */
export type DisplayStatus = 'pass' | 'fail' | 'deprecated' | 'untested';

export function displayStatus(c: CaseRecord): DisplayStatus {
  if (c.status === 'deprecated') return 'deprecated';
  const o = c.pcap?.outcome;
  if (o === 'pass') return 'pass';
  if (o === 'fail') return 'fail';
  return 'untested';
}

/**
 * Spec-order navigation (prev/next) computed once from index.json.
 * Deprecated cases are interleaved (see commit 5df1b40), so this list
 * matches the visual order on the index page.
 */
const orderedIds: string[] = indexFile.cases.map((e) => e.case_id);
const orderIndex: Record<string, number> = {};
orderedIds.forEach((id, i) => { orderIndex[id] = i; });

export function neighbours(caseId: string): {
  prev: CaseRecord | undefined;
  next: CaseRecord | undefined;
} {
  const i = orderIndex[caseId.toUpperCase()];
  if (i === undefined) return { prev: undefined, next: undefined };
  return {
    prev: i > 0 ? byId[orderedIds[i - 1]] : undefined,
    next: i < orderedIds.length - 1 ? byId[orderedIds[i + 1]] : undefined,
  };
}

/**
 * Group key derived from a case_id by stripping the trailing ``_NN``
 * counter, e.g. ``TCP_RETRANSMISSION_TO_04`` → ``TCP_RETRANSMISSION_TO``.
 * All 643 case ids match the ``<PREFIX>_<NUM>`` shape (verified against
 * site/src/data/index.json), so the regex is total.
 */
function groupKey(caseId: string): string {
  const m = caseId.toUpperCase().match(/^(.+?)_\d+$/);
  return m ? m[1] : caseId.toUpperCase();
}

/**
 * Distinct prefix bucket count per protocol — computed once. Protocols
 * with only one bucket (ARP, SOME/IP-ETS) have all their case_ids sharing
 * the same prefix, so prefix grouping degenerates to "everything"; those
 * fall back to section-based grouping. See sisterCases() rationale.
 */
const protocolPrefixCount: Record<string, number> = (() => {
  const buckets: Record<string, Set<string>> = {};
  for (const c of allCases) {
    const set = buckets[c.protocol] ?? (buckets[c.protocol] = new Set());
    set.add(groupKey(c.case_id));
  }
  const out: Record<string, number> = {};
  for (const [p, s] of Object.entries(buckets)) out[p] = s.size;
  return out;
})();

/**
 * Sister cases — natural sub-group within the same protocol.
 *
 * Hybrid resolution:
 *  1. **Prefix grouping** (default): cases sharing the ``<PREFIX>_NN``
 *     stem (e.g. ``REASSEMBLY``, ``RETRANSMISSION_TO``, ``FORMAT``).
 *     For most protocols this isolates the natural author-intended
 *     sub-group.
 *  2. **Section fallback**: when the protocol has only one distinct
 *     prefix (ARP shares ``ARP``; SOME/IP-ETS shares ``SOMEIP_ETS``),
 *     prefix grouping would just return everything in the protocol.
 *     Fall back to ``protocol + section`` so ARP §4.2.4.1 stays
 *     separate from §4.2.4.2.
 *
 * Windowing: when the group exceeds ``limit``, return a window of
 * ``limit`` cases centred on the current case in spec order — so
 * SOMEIP_ETS_007 shows its neighbours, not just the first 24 of 137.
 * The case itself is excluded from the result.
 */
export function sisterCases(c: CaseRecord, limit = 24): CaseRecord[] {
  const id = c.case_id.toUpperCase();
  const groupAll = sisterGroupAll(c);
  if (groupAll.length <= limit + 1) {
    return groupAll.filter((s) => s.case_id.toUpperCase() !== id);
  }
  const myIdx = groupAll.findIndex((s) => s.case_id.toUpperCase() === id);
  const half = Math.floor(limit / 2);
  let start = Math.max(0, myIdx - half);
  let end = start + limit + 1;
  if (end > groupAll.length) {
    end = groupAll.length;
    start = end - limit - 1;
  }
  return groupAll.slice(start, end).filter((s) => s.case_id.toUpperCase() !== id);
}

/** All cases in c's sister group (including c itself). */
function sisterGroupAll(c: CaseRecord): CaseRecord[] {
  const useSection = (protocolPrefixCount[c.protocol] ?? 0) <= 1;
  const myKey = groupKey(c.case_id);
  return allCases.filter((s) =>
    s.protocol === c.protocol &&
    (useSection ? s.section === c.section : groupKey(s.case_id) === myKey),
  );
}

export interface SisterGroupInfo {
  /** Human-readable group label ("FORMAT", "RETRANSMISSION_TO", or "§4.2.4.1"). */
  label: string;
  /** Total cases in the group, including c itself. */
  total: number;
  /** True if the rendered list is a window over a larger group. */
  windowed: boolean;
}

export function sisterGroupInfo(c: CaseRecord, limit = 24): SisterGroupInfo {
  const all = sisterGroupAll(c);
  const useSection = (protocolPrefixCount[c.protocol] ?? 0) <= 1;
  const protoStrip = c.protocol.replace(/[^A-Z0-9]/gi, '_').toUpperCase();
  const key = groupKey(c.case_id);
  // Strip protocol prefix from the key for a cleaner label, e.g.
  // ``TCP_RETRANSMISSION_TO`` → ``RETRANSMISSION_TO``.
  const trimmed = key.startsWith(protoStrip + '_') ? key.slice(protoStrip.length + 1) : key;
  return {
    label: useSection ? `§${c.section}` : trimmed,
    total: all.length,
    windowed: all.length > limit + 1,
  };
}
