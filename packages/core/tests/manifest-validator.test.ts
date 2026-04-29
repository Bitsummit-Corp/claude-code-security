import { describe, it, expect } from 'vitest';
import { validateManifest, ManifestError } from '../src/manifest-validator.js';

describe('validateManifest', () => {
  const valid = {
    name: 'secret-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-001-secret-leak',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  };

  it('accepts a valid manifest', () => {
    expect(() => validateManifest(valid)).not.toThrow();
  });

  it('rejects missing required fields', () => {
    const m = { ...valid } as Record<string, unknown>;
    delete m.threat;
    expect(() => validateManifest(m)).toThrow(ManifestError);
  });

  it('rejects unknown event types', () => {
    expect(() => validateManifest({ ...valid, event: 'AfterDinner' })).toThrow(ManifestError);
  });

  it('rejects timeout_ms below 100 or above 30000', () => {
    expect(() => validateManifest({ ...valid, timeout_ms: 50 })).toThrow(ManifestError);
    expect(() => validateManifest({ ...valid, timeout_ms: 60000 })).toThrow(ManifestError);
  });

  it('rejects empty matchers', () => {
    expect(() => validateManifest({ ...valid, matchers: [] })).toThrow(ManifestError);
  });

  it('rejects threat IDs not matching T-NNN pattern', () => {
    expect(() => validateManifest({ ...valid, threat: 'something' })).toThrow(ManifestError);
  });

  it('error message includes field path for nested failures', () => {
    try {
      validateManifest({ ...valid, severity: 'panic' });
      throw new Error('should have thrown');
    } catch (e) {
      expect(String(e)).toMatch(/severity/);
    }
  });
});
