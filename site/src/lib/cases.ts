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
 * Sister cases — same protocol AND same section number. Returns active
 * cases first (spec order), then deprecated. Excludes the case itself.
 * Cap at 24 to keep the sidebar reasonable on huge groups.
 */
export function sisterCases(c: CaseRecord, limit = 24): CaseRecord[] {
  const id = c.case_id.toUpperCase();
  const sisters = allCases.filter(
    (s) => s.protocol === c.protocol && s.section === c.section && s.case_id.toUpperCase() !== id,
  );
  return sisters.slice(0, limit);
}
