import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const MARKERS: { name: string; re: RegExp }[] = [
  { name: 'system-open-tag', re: /<system\b/i },
  { name: 'system-close-tag', re: /<\/system>/i },
  { name: 'cdata-wrapper', re: /<!\[CDATA\[/ },
  { name: 'ignore-previous', re: /Ignore previous/i },
  { name: 'system-prefix', re: /SYSTEM:/ },
];

function extractText(response: HookContext['response']): string {
  if (!response) return '';
  const parts: string[] = [];
  if (typeof response.stdout === 'string') parts.push(response.stdout);
  if (typeof response.stderr === 'string') parts.push(response.stderr);
  if (typeof response.output === 'string') parts.push(response.output);
  return parts.join('\n');
}

const untrustedContentTagger: HookModule = {
  manifest: {
    name: 'untrusted-content-tagger',
    event: 'PostToolUse',
    matchers: ['WebFetch', 'Read'],
    threat: 'T-010-prompt-injection',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'log',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const text = extractText(ctx.response);
    const matches: string[] = [];
    if (text.length > 0) {
      for (const m of MARKERS) {
        if (m.re.test(text)) matches.push(m.name);
      }
    }
    return {
      decision: 'allow',
      reason:
        matches.length > 0
          ? `untrusted content from ${ctx.tool} contains ${matches.length} injection marker(s)`
          : `${ctx.tool} response had no injection markers`,
      evidence: {
        kind: 'untrusted-content',
        source: ctx.tool,
        marker_count: matches.length,
        markers: matches,
      },
    };
  },
};

export default untrustedContentTagger;
