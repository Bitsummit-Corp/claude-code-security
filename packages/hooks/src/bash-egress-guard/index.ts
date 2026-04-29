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

const ALWAYS_BLOCK = new Set([
  'pastebin.com',
  'transfer.sh',
  'paste.ee',
  'requestbin.com',
]);

const DOH_HOSTS = new Set([
  'cloudflare-dns.com',
  'dns.google',
  'one.one.one.one',
  'mozilla.cloudflare-dns.com',
]);

const IP_LITERAL_RE = /^[\d.]+$|^\[[0-9a-fA-F:]+\]$/;
const NETWORK_TOOL_RE = /\b(curl|wget|fetch|http|https-get)\b/;
const URL_RE = /https?:\/\/[^\s'"`<>]+/g;
// Long base64 starting with "aHR0c" (decodes to "http"). Require at least
// 12 chars after the prefix so we don't fire on short coincidental tokens.
const BASE64_HTTP_RE = /\baHR0c[A-Za-z0-9+/=]{12,}\b/;

interface BlockResult {
  reason: string;
  evidence: Record<string, unknown>;
}

function classifyUrl(url: string): BlockResult | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const rawHost = parsed.hostname;
  const host = rawHost.toLowerCase();
  const hostBracketed =
    rawHost.startsWith('[') && rawHost.endsWith(']') ? rawHost : host;

  if (ALWAYS_BLOCK.has(host)) {
    return {
      reason: `host '${host}' is on the always-block exfil-target list (T-005)`,
      evidence: { kind: 'always-block', host, url },
    };
  }
  if (IP_LITERAL_RE.test(hostBracketed)) {
    return {
      reason: `IP-literal host '${rawHost}' in shell URL (T-005)`,
      evidence: { kind: 'ip-literal', host: rawHost, url },
    };
  }
  if (DOH_HOSTS.has(host)) {
    return {
      reason: `DNS-over-HTTPS host '${host}' is a known exfil channel (T-005)`,
      evidence: { kind: 'doh-host', host, url },
    };
  }
  return null;
}

const bashEgressGuard: HookModule = {
  manifest: {
    name: 'bash-egress-guard',
    event: 'PreToolUse',
    matchers: ['Bash'],
    threat: 'T-005-network-exfil',
    profiles: ['baseline', 'strict', 'regulated'],
    severity: { baseline: 'warn', strict: 'block', regulated: 'block' },
    timeout_ms: 1500,
  },
  async run(ctx: HookContext): Promise<HookDecision> {
    const cmd = typeof ctx.input.command === 'string' ? ctx.input.command : null;
    if (!cmd) return { decision: 'allow', reason: 'no command field' };

    if (BASE64_HTTP_RE.test(cmd)) {
      return {
        decision: 'block',
        reason: 'command contains base64-encoded HTTP URL (aHR0c...) suggesting exfil obfuscation',
        evidence: { kind: 'base64-url-heuristic' },
      };
    }

    if (!NETWORK_TOOL_RE.test(cmd)) {
      return { decision: 'allow', reason: 'no network tool invocation detected' };
    }

    const urls = cmd.match(URL_RE) ?? [];
    if (urls.length === 0) {
      return { decision: 'allow', reason: 'no URL in network-tool command' };
    }

    const nonAllowlistedHosts: string[] = [];
    for (const url of urls) {
      const blocking = classifyUrl(url);
      if (blocking) {
        return {
          decision: 'block',
          reason: blocking.reason,
          evidence: blocking.evidence,
        };
      }
      try {
        const host = new URL(url).hostname.toLowerCase();
        if (!ALLOWLIST.has(host)) nonAllowlistedHosts.push(host);
      } catch {
        // Unparseable URL inside command -> treat as suspicious / non-allow.
        nonAllowlistedHosts.push(url);
      }
    }

    if (nonAllowlistedHosts.length === 0) {
      return { decision: 'allow', reason: 'all URLs are allowlisted' };
    }

    return {
      decision: 'warn',
      reason: `network call to non-allowlisted host(s): ${nonAllowlistedHosts.join(', ')} (T-005)`,
      evidence: { kind: 'non-allowlisted-host', hosts: nonAllowlistedHosts },
    };
  },
};

export default bashEgressGuard;
