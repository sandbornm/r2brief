import { existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';
import { describe, expect, it } from 'vitest';
import { muiIconComponent } from './src/muiIconInterop';

const root = process.cwd();

function iconDepSpecifier(code: string): string | undefined {
  const direct = code.match(/import\s+__muiIcon_SettingsIcon\s+from\s+["']([^"']+)["']/)?.[1];
  if (direct) {
    return direct;
  }
  const alias = code.match(/const __muiIcon_SettingsIcon = ([A-Za-z0-9_$]+)/)?.[1];
  if (!alias) {
    return undefined;
  }
  return code.match(new RegExp(`import ${alias} from ["']([^"']+)["']`))?.[1];
}

function materializedDep(specifier: string, base: string): string {
  const url = new URL(specifier, base);
  const relative = decodeURIComponent(url.pathname).replace(/^\/+/, '');
  const direct = path.join(root, relative);
  if (existsSync(direct)) {
    return direct;
  }
  const baseName = path.basename(relative);
  const found: string[] = [];
  const walk = (current: string) => {
    for (const name of readdirSync(current)) {
      const full = path.join(current, name);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (name === baseName) {
        found.push(full);
      }
    }
  };
  walk(path.join(root, 'node_modules/.vite'));
  const newest = found.sort((left, right) => statSync(right).mtimeMs - statSync(left).mtimeMs)[0];
  if (!newest) {
    throw new Error(`Vite did not materialize the imported icon module ${baseName}`);
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
      const transformedCode = transformed?.code ?? '';
      expect(transformedCode).toContain('muiIconComponent(__muiIcon_SettingsIcon)');
      const depSpecifier = iconDepSpecifier(transformedCode);
      expect(depSpecifier).toBeTruthy();
      const base = server.resolvedUrls?.local?.[0];
      expect(base).toBeTruthy();
      const depResponse = await fetch(new URL(depSpecifier!, base));
      expect(depResponse.status).toBe(200);
      expect(await depResponse.text()).toContain('export default');
      const optimized = (await import(pathToFileURL(materializedDep(depSpecifier!, base!)).href)) as {
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
