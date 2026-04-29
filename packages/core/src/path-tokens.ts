export type TargetOS = 'macos' | 'linux' | 'windows';

export function resolveTokens(
  input: string,
  os: TargetOS,
  env: Readonly<Record<string, string | undefined>>,
): string {
  const home = os === 'windows' ? env.USERPROFILE : env.HOME;
  if (!home && /\$\{(HOME|SSH|AWS|KEYS)\}/.test(input)) {
    throw new Error(`HOME not set in environment for OS=${os}`);
  }
  const tmp = os === 'windows' ? (env.TEMP ?? `${home}\\AppData\\Local\\Temp`) : '/tmp';
  const keysList = [
    `${home}/.ssh`,
    `${home}/.aws`,
    `${home}/.gnupg`,
    `${home}/.kube`,
    `${home}/.docker`,
  ].join('|');

  return input.replace(/\$\{([A-Z_]+)\}/g, (_match, name: string) => {
    switch (name) {
      case 'HOME': return home ?? '${HOME}';
      case 'SSH':  return `${home}/.ssh`;
      case 'AWS':  return `${home}/.aws`;
      case 'TMP':  return tmp;
      case 'KEYS': return keysList;
      default:     return `\${${name}}`;
    }
  });
}
