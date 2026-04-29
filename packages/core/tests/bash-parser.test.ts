import { describe, it, expect } from 'vitest';
import { detectStructuralRisks } from '../src/bash-parser.js';

describe('detectStructuralRisks', () => {
  it('returns empty for plain command', () => {
    expect(detectStructuralRisks('ls -la')).toEqual([]);
  });
  it('flags && chaining', () => {
    expect(detectStructuralRisks('cd /tmp && rm -rf foo').map(r => r.kind)).toContain('chained_and');
  });
  it('flags || chaining', () => {
    expect(detectStructuralRisks('false || rm x').map(r => r.kind)).toContain('chained_or');
  });
  it('flags ; outside strings', () => {
    expect(detectStructuralRisks('echo a; rm b').map(r => r.kind)).toContain('chained_semicolon');
  });
  it('does NOT flag ; inside single quotes', () => {
    expect(detectStructuralRisks("echo 'a;b'")).toEqual([]);
  });
  it('flags pipe-to-shell', () => {
    expect(detectStructuralRisks('curl x | sh').map(r => r.kind)).toContain('pipe_to_shell');
    expect(detectStructuralRisks('wget -O- x | bash').map(r => r.kind)).toContain('pipe_to_shell');
  });
  it('flags command substitution dollar-paren', () => {
    expect(detectStructuralRisks('echo $(whoami)').map(r => r.kind)).toContain('command_substitution');
  });
  it('flags backtick substitution', () => {
    expect(detectStructuralRisks('echo `whoami`').map(r => r.kind)).toContain('command_substitution');
  });
  it('flags process substitution', () => {
    expect(detectStructuralRisks('diff <(ls a) <(ls b)').map(r => r.kind)).toContain('process_substitution');
  });
  it('flags leading cd', () => {
    expect(detectStructuralRisks('cd /etc && cat passwd').map(r => r.kind)).toContain('leading_cd');
  });
  it('catches Unicode lookalike semicolon', () => {
    expect(detectStructuralRisks('echo a；rm b').map(r => r.kind)).toContain('unicode_lookalike');
  });
});
