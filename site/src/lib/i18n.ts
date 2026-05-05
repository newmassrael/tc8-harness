import en from '../locales/en.json';
import ko from '../locales/ko.json';
import type { Locale } from './types';

const dict = { en, ko } as const;

export type TKey = keyof typeof en;

export function t(locale: Locale, key: TKey): string {
  return (dict[locale] as Record<string, string>)[key] ?? (en as Record<string, string>)[key] ?? key;
}

export const locales: Locale[] = ['en', 'ko'];
