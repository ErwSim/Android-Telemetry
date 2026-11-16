import { describe, expect, it } from 'vitest';
import { cleanText } from './text.ts';

describe('cleanText (text coming from a third-party application)', () => {
  it('leaves markup as is: it is only text', () => {
    expect(cleanText('<img src=x onerror=alert(1)> **bold** [link](javascript:1)')).toBe('<img src=x onerror=alert(1)> **bold** [link](javascript:1)');
  });
  it('removes control and bidirectional reordering characters', () => {
    expect(cleanText('a‮b\u0007c⁦d')).toBe('abcd');
  });
  it('flattens line breaks', () => {
    expect(cleanText('l1\nl2\r\nl3')).toBe('l1 ⏎ l2 ⏎ l3');
  });
  it('truncates to 512 characters by default and ignores non-strings', () => {
    expect(Array.from(cleanText('ß'.repeat(600)))).toHaveLength(513);
    expect(cleanText(42)).toBe('');
    expect(cleanText(undefined)).toBe('');
  });
});
