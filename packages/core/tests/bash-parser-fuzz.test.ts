import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { detectStructuralRisks } from '../src/bash-parser.js';

describe('bash-parser fuzz', () => {
  it('never throws on any printable input', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 0, maxLength: 200 }),
        (cmd) => {
          expect(() => detectStructuralRisks(cmd)).not.toThrow();
        },
      ),
      { numRuns: 200 },
    );
  });

  it('always returns an array', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 100 }), (cmd) => {
        expect(Array.isArray(detectStructuralRisks(cmd))).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('detects pipe-to-shell when generated', () => {
    // URL alphabet excludes quote chars and pipe so the masker cannot consume the pipe
    fc.assert(
      fc.property(
        fc.constantFrom('curl', 'wget', 'fetch'),
        fc.stringMatching(/^[a-zA-Z0-9:/.\-_?=&]{1,30}$/),
        fc.constantFrom('sh', 'bash', 'zsh'),
        (fetch, url, shell) => {
          const cmd = `${fetch} ${url} | ${shell}`;
          const risks = detectStructuralRisks(cmd);
          expect(risks.map(r => r.kind)).toContain('pipe_to_shell');
        },
      ),
      { numRuns: 50 },
    );
  });

  it('returns empty for purely alphanumeric input', () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[a-zA-Z0-9 ]+$/), (cmd) => {
        // Pure alphanumeric input has no structural risks unless it triggers leading-cd which requires "cd "
        if (!cmd.trim().startsWith('cd ')) {
          expect(detectStructuralRisks(cmd)).toEqual([]);
        }
      }),
      { numRuns: 100 },
    );
  });
});
