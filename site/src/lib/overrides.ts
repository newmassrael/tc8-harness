/**
 * Per-case content overrides.
 *
 * Drop a JSON file at ``site/src/locales/cases/<locale>/<CASE_ID>.json``
 * (locale = ``en`` or ``ko``) with any subset of the fields below.
 * Anything not provided falls back through:
 *   ko → ko override → en override → trait header (with fallback marker)
 *   en → en override → trait header (no marker)
 *
 * Recommended structure for ``approach`` — make each page self-contained
 * so the reader doesn't need the spec PDF:
 *
 *   [검증 목적]      — 무엇을 확인하는지 1-3문장
 *   [시나리오]       — 시간순 단계, 누가(테스터/DUT) 무엇을 보내는지 명시
 *   [통과 조건]      — 무엇을 보면 PASS인지
 *   [실패 조건]      — 어떤 상황이 FAIL이고 왜인지 (verdict 별 매핑)
 *
 * Schema:
 *
 *     {
 *       "description": "한 줄 요약",
 *       "approach": "여러 줄 시나리오 서술",
 *       "verdicts": {
 *         "<SCXML state name>": "한글 의미"
 *       }
 *     }
 */

import type { CaseRecord, Locale, MessageHighlight } from './types';

export interface CaseOverride {
  description?: string;
  approach?: string;
  verdicts?: Record<string, string>;
  /** Important-message highlights for the packet timeline.
   * ``idx`` selects the packet by 0-based index in the capture. */
  messages?: MessageHighlight[];
}

function buildMap(modules: Record<string, CaseOverride>): Record<string, CaseOverride> {
  const out: Record<string, CaseOverride> = {};
  for (const [path, mod] of Object.entries(modules)) {
    const id = path.split('/').pop()!.replace(/\.json$/, '').toUpperCase();
    out[id] = mod;
  }
  return out;
}

// Base locales come from the tracked source tree; OEM overlay locales are
// staged (git-ignored) into ../data/extra_locales/<lang>/ by build_manifest.py
// from each SITE_EXTRA_CASE_ROOTS root. Both globs resolve fixed in-tree
// paths at build time (Vite requirement); the extra dir is empty for a
// public build, so the merged map is byte-identical when the var is unset.
// Extra entries are spread last so an extra root wins on a same-id collision
// (case_ids are required disjoint, so this is only a documented tie-break).
const koMap = buildMap({
  ...import.meta.glob<CaseOverride>('../locales/cases/ko/*.json', { eager: true, import: 'default' }),
  ...import.meta.glob<CaseOverride>('../data/extra_locales/ko/*.json', { eager: true, import: 'default' }),
});
const enMap = buildMap({
  ...import.meta.glob<CaseOverride>('../locales/cases/en/*.json', { eager: true, import: 'default' }),
  ...import.meta.glob<CaseOverride>('../data/extra_locales/en/*.json', { eager: true, import: 'default' }),
});

interface AutoMessages {
  case_id: string;
  generator_version: string;
  messages: MessageHighlight[];
}

function buildAutoMap(modules: Record<string, AutoMessages>): Record<string, MessageHighlight[]> {
  const out: Record<string, MessageHighlight[]> = {};
  for (const [path, mod] of Object.entries(modules)) {
    const id = path.split('/').pop()!.replace(/\.json$/, '').toUpperCase();
    out[id] = mod.messages ?? [];
  }
  return out;
}

const autoMap = buildAutoMap(import.meta.glob<AutoMessages>(
  '../data/auto_messages/*.json', { eager: true, import: 'default' }));

export interface TranslationCoverage {
  en: number;
  ko: number;
  total: number;
}

/**
 * Coverage counted against the *rendered* case set only. ``import.meta.glob``
 * eagerly loads every locale file on disk (public + every OEM overlay root),
 * but a subset or overlay-only build renders fewer cases — so counting raw
 * map size would report coverage greater than the total. Intersecting with
 * the rendered ids keeps ``en``/``ko`` ≤ ``total`` for any build; for a full
 * public build every locale id is rendered, so the count is unchanged.
 */
export function translationCoverage(caseIds: Iterable<string>): TranslationCoverage {
  const rendered = new Set<string>();
  for (const id of caseIds) rendered.add(id.toUpperCase());
  const inRendered = (id: string) => rendered.has(id);
  return {
    en: Object.keys(enMap).filter(inRendered).length,
    ko: Object.keys(koMap).filter(inRendered).length,
    total: rendered.size,
  };
}

export function hasOverride(caseId: string, locale: Locale): boolean {
  const id = caseId.toUpperCase();
  return locale === 'ko' ? id in koMap : id in enMap;
}

export interface LocalizedField {
  text: string;
  isFallback: boolean;
}

function pick(c: CaseRecord, locale: Locale, getter: (o: CaseOverride) => string | undefined,
              traitFallback: string): LocalizedField {
  const id = c.case_id.toUpperCase();
  if (locale === 'ko') {
    const ko = koMap[id]; const ov = ko && getter(ko);
    if (ov) return { text: ov, isFallback: false };
  }
  const en = enMap[id]; const ovEn = en && getter(en);
  if (ovEn) return { text: ovEn, isFallback: locale !== 'en' };
  return { text: traitFallback, isFallback: locale !== 'en' };
}

export function localizedDescription(c: CaseRecord, locale: Locale): LocalizedField {
  return pick(c, locale, (o) => o.description, c.trait?.description ?? '');
}

export function localizedApproach(c: CaseRecord, locale: Locale): LocalizedField {
  return pick(c, locale, (o) => o.approach, c.trait?.approach ?? '');
}

export function localizedVerdictMeaning(
  c: CaseRecord, locale: Locale, state: string,
): string | undefined {
  const id = c.case_id.toUpperCase();
  if (locale === 'ko') {
    const v = koMap[id]?.verdicts?.[state];
    if (v) return v;
  }
  return enMap[id]?.verdicts?.[state];
}

/**
 * Merge per-packet messages across (ko-manual, en-manual, auto, empty)
 * sources at idx granularity. The first source that owns a given idx wins
 * — manual annotations override auto output but only for the specific
 * packets the author wrote labels for; auto fills the rest.
 *
 * Priority per idx:
 *   ko manual → en manual → auto → (skip)
 *
 * Returned list is sorted by idx ascending.
 */
export function localizedMessages(c: CaseRecord, locale: Locale): MessageHighlight[] {
  const id = c.case_id.toUpperCase();
  const ko = locale === 'ko' ? (koMap[id]?.messages ?? []) : [];
  const en = enMap[id]?.messages ?? [];
  const auto = autoMap[id] ?? [];

  const out = new Map<number, MessageHighlight>();
  for (const m of auto) out.set(m.idx, m);
  for (const m of en) out.set(m.idx, m);
  for (const m of ko) out.set(m.idx, m);

  return [...out.values()].sort((a, b) => a.idx - b.idx);
}
