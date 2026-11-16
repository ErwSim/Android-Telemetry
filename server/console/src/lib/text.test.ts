import { describe, expect, it } from 'vitest';
import { cleanText } from './text.ts';

describe('cleanText (texte venant d’une application tierce)', () => {
  it('laisse le balisage tel quel : ce n’est que du texte', () => {
    expect(cleanText('<img src=x onerror=alert(1)> **gras** [lien](javascript:1)')).toBe('<img src=x onerror=alert(1)> **gras** [lien](javascript:1)');
  });
  it('retire les caractères de contrôle et de réordonnancement bidirectionnel', () => {
    expect(cleanText('a‮b\u0007c⁦d')).toBe('abcd');
  });
  it('aplatit les retours à la ligne', () => {
    expect(cleanText('l1\nl2\r\nl3')).toBe('l1 ⏎ l2 ⏎ l3');
  });
  it('tronque à 512 caractères par défaut et ignore les non-chaînes', () => {
    expect(Array.from(cleanText('é'.repeat(600)))).toHaveLength(513);
    expect(cleanText(42)).toBe('');
    expect(cleanText(undefined)).toBe('');
  });
});
