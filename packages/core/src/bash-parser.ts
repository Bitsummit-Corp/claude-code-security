export type StructuralRiskKind =
  | 'chained_and'
  | 'chained_or'
  | 'chained_semicolon'
  | 'pipe_to_shell'
  | 'command_substitution'
  | 'process_substitution'
  | 'leading_cd'
  | 'unicode_lookalike'
  | 'background_operator';

export interface StructuralRisk {
  kind: StructuralRiskKind;
  offset: number;
  excerpt: string;
}

const UNICODE_LOOKALIKES = new Set(['；', '＆', '｜', '＄']);

// Note: maskQuotedRegions does not honor `\` escape sequences inside double-quoted
// strings. The conservative tradeoff is over-flagging on malformed quotes (which
// is safer than under-flagging risky shell metacharacters).
function maskQuotedRegions(cmd: string): string {
  const out: string[] = [];
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i] as string;
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    out.push(inSingle || inDouble ? ' ' : ch);
  }
  return out.join('');
}

export function detectStructuralRisks(cmd: string): StructuralRisk[] {
  const risks: StructuralRisk[] = [];
  const masked = maskQuotedRegions(cmd);

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i] as string;
    if (UNICODE_LOOKALIKES.has(ch)) {
      risks.push({
        kind: 'unicode_lookalike',
        offset: i,
        excerpt: cmd.slice(Math.max(0, i - 5), i + 5),
      });
    }
  }

  const scan = (re: RegExp, kind: StructuralRiskKind) => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(masked)) !== null) {
      risks.push({ kind, offset: m.index, excerpt: cmd.slice(m.index, m.index + m[0].length) });
    }
  };

  scan(/&&/g, 'chained_and');
  scan(/\|\|/g, 'chained_or');
  scan(/;/g, 'chained_semicolon');
  scan(/\|\s*(?:sh|bash|zsh|fish|ksh)\b/g, 'pipe_to_shell');
  scan(/\$\([^)]*\)/g, 'command_substitution');
  scan(/`[^`]*`/g, 'command_substitution');
  scan(/[<>]\([^)]*\)/g, 'process_substitution');
  scan(/(?<!&)&(?!&)/g, 'background_operator');

  if (/^\s*cd\s+\S+/.test(cmd)) {
    risks.push({ kind: 'leading_cd', offset: 0, excerpt: cmd.split(/\s+/).slice(0, 2).join(' ') });
  }

  return risks.sort((a, b) => a.offset - b.offset);
}
