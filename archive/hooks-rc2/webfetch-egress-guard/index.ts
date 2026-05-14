import type { HookModule, HookContext, HookDecision } from '@bitsummit/ccsec-core';

const ALLOWLIST = new Set([
  'docs.anthropic.com',
  'github.com',
  'raw.githubusercontent.com',
  'api.github.com',
  'developer.mozilla.org',
  'nodejs.org',
  'registry.npmjs.org',
  'pypi.org',
]);

const DOH_HOSTS = new Set([
  'cloudflare-dns.com',
  'dns.google',
  'one.one.one.one',
  'mozilla.cloudflare-dns.com',
]);

const IP_LITERAL_RE = /^[\d.]+$|^\[[0-9a-fA-F:]+\]$/;

const webfetchEgressGuard: HookModule = {
  manifest: {
    name: 'webfetch-egress-guard',
    event: 'PreToolUse',
    matchers: ['WebFetch'],
    threat: 'T-005-network-exfil',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: 'block',
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const url = ctx.input.url;
    if (typeof url !== 'string') {
      return { decision: 'allow', reason: 'no string url field' };
    }

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return {
        decision: 'block',
        reason: `malformed url '${url}' rejected as suspicious`,
        evidence: { kind: 'malformed-url', url },
      };
    }

    const host = parsed.hostname.toLowerCase();
    const hostBracketed =
      parsed.hostname.startsWith('[') && parsed.hostname.endsWith(']') ? parsed.hostname : host;

    if (IP_LITERAL_RE.test(hostBracketed)) {
      return {
        decision: 'block',
        reason: `IP-literal host '${parsed.hostname}' is not allowlisted (T-005)`,
        evidence: { kind: 'ip-literal', host: parsed.hostname, url },
      };
    }

    if (DOH_HOSTS.has(host)) {
      return {
        decision: 'block',
        reason: `DNS-over-HTTPS host '${host}' is a known exfil channel (T-005)`,
        evidence: { kind: 'doh-host', host, url },
      };
    }

    if (!ALLOWLIST.has(host)) {
      return {
        decision: 'block',
        reason: `host '${host}' is not in the WebFetch allowlist (T-005, deny-by-default)`,
        evidence: { kind: 'not-allowlisted', host, url },
      };
    }

    return { decision: 'allow', reason: `host '${host}' is allowlisted` };
  },
};

export default webfetchEgressGuard;
