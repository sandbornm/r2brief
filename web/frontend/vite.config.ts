import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { rewriteMuiIconDefaultImports } from './src/muiIconInterop.ts';

const muiIconHelper = fileURLToPath(new URL('./src/muiIconInterop.ts', import.meta.url));

// The dev prebundle serves @mui/icons-material defaults as { default: Icon }.
function muiIconDefaultInterop() {
  return {
    name: 'mui-icon-default-interop',
    enforce: 'pre' as const,
    transform(code: string, id: string) {
      const filename = id.split('?', 1)[0];
      if (!filename.includes(`${path.sep}src${path.sep}`) || filename.includes(`${path.sep}node_modules${path.sep}`)) {
        return null;
      }
      if (!code.includes('@mui/icons-material/')) {
        return null;
      }
      let helperSpecifier = path.relative(path.dirname(filename), muiIconHelper).replace(/\\/g, '/').replace(/\.ts$/, '');
      if (!helperSpecifier.startsWith('.')) {
        helperSpecifier = `./${helperSpecifier}`;
      }
      const next = rewriteMuiIconDefaultImports(code, helperSpecifier);
      if (next === code) {
        return null;
      }
      return { code: next, map: null };
    },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'VITE_');
  const apiTarget = env.VITE_R2B_API_BASE || 'http://127.0.0.1:5050';

  return {
  plugins: [react(), muiIconDefaultInterop()],
  server: {
    port: 5173,
    host: '127.0.0.1',
    // Tailscale Serve / MagicDNS hits Vite with the public hostname.
    allowedHosts: [
      'kali-raspberry-pi5.tailcba5f3.ts.net',
      '.ts.net',
    ],
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          const normalizedId = id.replace(/\\/g, '/');
          if (
            normalizedId.includes('/node_modules/react/') ||
            normalizedId.includes('/node_modules/react-dom/') ||
            normalizedId.includes('/node_modules/scheduler/')
          ) {
            return 'react-vendor';
          }
          if (
            normalizedId.includes('/node_modules/@mui/') ||
            normalizedId.includes('/node_modules/@emotion/') ||
            normalizedId.includes('/node_modules/react-is/')
          ) {
            return 'mui-vendor';
          }
          if (normalizedId.includes('/node_modules/@codemirror/') || normalizedId.includes('/node_modules/@lezer/')) {
            return 'codemirror-vendor';
          }
          if (normalizedId.includes('/node_modules/react-markdown/') || normalizedId.includes('/node_modules/remark-gfm/')) {
            return 'markdown-vendor';
          }
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    coverage: {
      reporter: ['text', 'lcov'],
    },
  },
  };
});
