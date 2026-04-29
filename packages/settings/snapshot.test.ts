import { describe, it, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

async function read(name: string): Promise<string> {
  return readFile(join(here, 'compiled', `${name}.json`), 'utf8');
}

describe('settings/compiled snapshots', () => {
  it('baseline.json matches checked-in snapshot', async () => {
    expect(await read('baseline')).toMatchSnapshot();
  });
  it('strict.json matches checked-in snapshot', async () => {
    expect(await read('strict')).toMatchSnapshot();
  });
  it('regulated.json matches checked-in snapshot', async () => {
    expect(await read('regulated')).toMatchSnapshot();
  });
});
