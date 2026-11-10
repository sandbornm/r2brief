import { describe, expect, it } from 'vitest';
import { muiIconComponent, rewriteMuiIconDefaultImports } from '../muiIconInterop';

describe('mui icon dev interop', () => {
  it('keeps a component function', () => {
    const Icon = () => null;
    expect(muiIconComponent(Icon)).toBe(Icon);
  });

  it('unwraps a prebundled default that nested the component', () => {
    const Icon = () => null;
    expect(muiIconComponent({ default: Icon })).toBe(Icon);
  });

  it('unwraps a forwardRef icon nested on the prebundle default', () => {
    const Icon = { $$typeof: Symbol.for('react.forward_ref'), render: () => null };
    expect(muiIconComponent(Icon)).toBe(Icon);
    expect(muiIconComponent({ __esModule: true, default: Icon })).toBe(Icon);
  });

  it('rewrites default icon imports once', () => {
    const source = [
      "import SettingsIcon from '@mui/icons-material/Settings';",
      "import AddIcon from '@mui/icons-material/Add';",
      'export const icons = [SettingsIcon, AddIcon];',
      '',
    ].join('\n');

    const next = rewriteMuiIconDefaultImports(source, '../muiIconInterop');

    expect(next).toContain('import { muiIconComponent } from "../muiIconInterop";');
    expect(next).toContain("import __muiIcon_SettingsIcon from '@mui/icons-material/Settings';");
    expect(next).toContain('const SettingsIcon = muiIconComponent(__muiIcon_SettingsIcon);');
    expect(next).toContain("import __muiIcon_AddIcon from '@mui/icons-material/Add';");
    expect(next).toContain('export const icons = [SettingsIcon, AddIcon];');
    expect(next.match(/import \{ muiIconComponent \}/g)).toHaveLength(1);
    expect(rewriteMuiIconDefaultImports(next, '../muiIconInterop')).toBe(next);
  });
});
