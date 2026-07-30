import en from '../locales/en.json';
import ko from '../locales/ko.json';
import type { Locale } from './types';

const dict = { en, ko } as const;

export type TKey = keyof typeof en;

export function t(locale: Locale, key: TKey): string {
  return (dict[locale] as Record<string, string>)[key] ?? (en as Record<string, string>)[key] ?? key;
}

/**
 * ``t`` with ``{name}`` placeholders filled from ``vars``.
 *
 * Interpolation lives here rather than as a ``.replace`` at each call site so a
 * translator sees one substitution syntax across every locale file, and word
 * order stays the translator's to choose — ko puts the number first
 * (``{frame}번 …``) where en puts it third. An unknown placeholder is left
 * standing rather than blanked: a visible ``{frame}`` in the page names the
 * missing variable, where an empty string would just read as a wording bug.
 */
export function tf(locale: Locale, key: TKey, vars: Record<string, string | number>): string {
  return t(locale, key).replace(/\{(\w+)\}/g, (whole, name) =>
    name in vars ? String(vars[name]) : whole);
}

export const locales: Locale[] = ['en', 'ko'];
