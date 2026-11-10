import { describe, expect, it } from 'vitest';
import { isAppSourceModule, rewriteMuiIconImports } from '../../muiIconRewrite';
import { muiIconComponent } from '../muiIconInterop';

describe('mui icon dev interop', () => {
  it('keeps a component function and a forwardRef', () => {
    const Icon = () => null;
    const forwardRef = { $$typeof: Symbol.for('react.forward_ref'), render: Icon };
    expect(muiIconComponent(Icon)).toBe(Icon);
    expect(muiIconComponent(forwardRef)).toBe(forwardRef);
  });

  it('unwraps a prebundled default and a nested namespace default', () => {
    const Icon = { $$typeof: Symbol.for('react.forward_ref'), render: () => null };
    expect(muiIconComponent({ __esModule: true, default: Icon })).toBe(Icon);
    expect(muiIconComponent({ default: { __esModule: true, default: Icon } })).toBe(Icon);
  });

  it('rewrites multiline, named, and namespace icon imports once', () => {
    const source = [
      'import SettingsIcon from',
      "  '@mui/icons-material/Settings';",
      'import {',
      '  Add as AddIcon,',
      '  type SvgIconProps,',
      "} from '@mui/icons-material';",
      "import * as DeleteIcon from '@mui/icons-material/Delete';",
      'const mention = "import Skip from \'@mui/icons-material/Skip\';";',
      'export const icons = [SettingsIcon, AddIcon, DeleteIcon];',
      '',
    ].join('\n');

    const next = rewriteMuiIconImports(source, '../muiIconInterop');

    expect(next).toContain('import { muiIconComponent } from "../muiIconInterop";');
    expect(next).toContain("import __muiIcon_SettingsIcon from '@mui/icons-material/Settings';");
    expect(next).toContain('const SettingsIcon = muiIconComponent(__muiIcon_SettingsIcon);');
    expect(next).toContain("import { Add as __muiIcon_AddIcon, type SvgIconProps } from '@mui/icons-material';");
    expect(next).toContain('const AddIcon = muiIconComponent(__muiIcon_AddIcon);');
    expect(next).toContain("import * as __muiIcon_DeleteIcon from '@mui/icons-material/Delete';");
    expect(next).toContain('const DeleteIcon = muiIconComponent(__muiIcon_DeleteIcon);');
    expect(next).toContain('const mention = "import Skip from \'@mui/icons-material/Skip\';";');
    expect(next.match(/import \{ muiIconComponent \}/g)).toHaveLength(1);
    expect(rewriteMuiIconImports(next, '../muiIconInterop')).toBe(next);
  });

  it('treats Windows and POSIX source paths the same', () => {
    expect(isAppSourceModule('C:\\repo\\web\\frontend\\src\\App.tsx')).toBe(true);
    expect(isAppSourceModule('/repo/web/frontend/src/App.tsx?t=1')).toBe(true);
    expect(isAppSourceModule('C:\\repo\\web\\frontend\\node_modules\\pkg\\src\\index.js')).toBe(false);
    expect(isAppSourceModule('/repo/web/frontend/node_modules/@mui/icons-material/Settings.js')).toBe(false);
  });
});
