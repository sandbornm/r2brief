import { readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { describe, expect, it } from 'vitest';
import { muiIconComponent } from './src/muiIconInterop';

const root = process.cwd();

function newestOptimizedSettingsIcon(): string {
  const found: string[] = [];
  const walk = (current: string) => {
    for (const name of readdirSync(current)) {
      const full = path.join(current, name);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (name === '@mui_icons-material_Settings.js') {
        found.push(full);
      }
    }
  };
  walk(path.join(root, 'node_modules/.vite'));
  const newest = found.sort((left, right) => statSync(right).mtimeMs - statSync(left).mtimeMs)[0];
  if (!newest) {
    throw new Error('Vite did not prebundle @mui/icons-material/Settings');
  }
  return newest;
}

describe('mui icon dev pipeline', () => {
  it('renders a Settings icon through the Vite dev server', async () => {
    const server = await createServer({
      configFile: path.join(root, 'vite.config.ts'),
      root,
      server: { host: '127.0.0.1', port: 0 },
      logLevel: 'error',
    });
    try {
      await server.listen();
      const transformed = await server.transformRequest('/src/__tests__/fixtures/IconProbe.tsx');
      expect(transformed?.code).toContain('muiIconComponent(__muiIcon_SettingsIcon)');
      expect(transformed?.code).toContain('/@mui_icons-material_Settings.js');

      const depPath = transformed?.code.match(/"(\/node_modules\/\.vite\/deps\/@mui_icons-material_Settings\.js[^"]*)"/)?.[1];
      expect(depPath).toBeTruthy();
      const base = server.resolvedUrls?.local?.[0];
      expect(base).toBeTruthy();
      const depResponse = await fetch(new URL(depPath!, base));
      expect(depResponse.status).toBe(200);
      expect(await depResponse.text()).toContain('export default');
      const optimized = (await import(pathToFileURL(newestOptimizedSettingsIcon()).href)) as {
        default: unknown;
      };
      expect(typeof optimized.default).not.toBe('function');
      const icon = muiIconComponent(optimized.default) as { $$typeof?: symbol };
      expect(typeof icon.$$typeof).toBe('symbol');

      const loaded = await server.ssrLoadModule('/src/__tests__/fixtures/IconProbe.tsx');
      const html = renderToStaticMarkup(createElement(loaded.default));
      expect(html).toContain('<svg');
      expect(html).toContain('M19.14 12.94');
    } finally {
      await server.close();
    }
  }, 30_000);
});
