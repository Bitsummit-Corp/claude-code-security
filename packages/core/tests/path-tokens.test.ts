import { describe, it, expect } from 'vitest';
import { resolveTokens } from '../src/path-tokens.js';

const env = (home: string) => ({ HOME: home, USERPROFILE: home });

describe('resolveTokens', () => {
  it('expands HOME on macOS', () => {
    expect(resolveTokens('${HOME}/.config', 'macos', env('/Users/x'))).toBe('/Users/x/.config');
  });
  it('expands HOME on linux', () => {
    expect(resolveTokens('${HOME}/.config', 'linux', env('/home/x'))).toBe('/home/x/.config');
  });
  it('expands HOME on windows', () => {
    expect(resolveTokens('${HOME}/.config', 'windows', env('C:\\Users\\x'))).toBe('C:\\Users\\x/.config');
  });
  it('expands SSH', () => {
    expect(resolveTokens('${SSH}/id_rsa', 'macos', env('/Users/x'))).toBe('/Users/x/.ssh/id_rsa');
  });
  it('expands AWS', () => {
    expect(resolveTokens('${AWS}/credentials', 'linux', env('/home/x'))).toBe('/home/x/.aws/credentials');
  });
  it('expands TMP per-OS', () => {
    expect(resolveTokens('${TMP}/x', 'macos', env('/Users/x'))).toBe('/tmp/x');
    expect(resolveTokens('${TMP}/x', 'linux', env('/home/x'))).toBe('/tmp/x');
  });
  it('expands KEYS to a list joined by |', () => {
    const out = resolveTokens('${KEYS}', 'macos', env('/Users/x'));
    expect(out).toContain('/Users/x/.ssh');
    expect(out.split('|').length).toBeGreaterThanOrEqual(3);
  });
  it('leaves unknown tokens intact', () => {
    expect(resolveTokens('${UNKNOWN}/x', 'macos', env('/Users/x'))).toBe('${UNKNOWN}/x');
  });
  it('throws on missing HOME', () => {
    expect(() => resolveTokens('${HOME}', 'macos', {})).toThrow(/HOME/);
  });
});
