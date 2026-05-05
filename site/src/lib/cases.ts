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
