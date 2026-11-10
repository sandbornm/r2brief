const MUI_ICON_DEFAULT_IMPORT =
  /^([ \t]*)import\s+([A-Za-z_$][\w$]*)\s+from\s+(['"])(@mui\/icons-material\/[^'"]+)\3;?[ \t]*$/gm;

function isRenderableComponent(value: unknown): boolean {
  return typeof value === 'function' || (value != null && typeof value === 'object' && '$$typeof' in value);
}

/**
 * Vite's dependency prebundle can hand React 19 an MUI icon as
 * `{ default: Component }` instead of the component. `createSvgIcon`
 * returns a forwardRef object, so the nested default is not a function.
 * Production builds already receive the component, and this leaves that
 * shape alone.
 */
export function muiIconComponent(imported: unknown): unknown {
  if (isRenderableComponent(imported)) {
    return imported;
  }
  if (
    imported != null &&
    typeof imported === 'object' &&
    'default' in imported &&
    isRenderableComponent(imported.default)
  ) {
    return imported.default;
  }
  return imported;
}

export function rewriteMuiIconDefaultImports(code: string, helperSpecifier: string): string {
  if (!code.includes('@mui/icons-material/')) {
    return code;
  }

  let rewrote = false;
  const next = code.replace(
    MUI_ICON_DEFAULT_IMPORT,
    (match, indent: string, local: string, quote: string, specifier: string) => {
      if (local.startsWith('__muiIcon_')) {
        return match;
      }
      rewrote = true;
      const raw = `__muiIcon_${local}`;
      return `${indent}import ${raw} from ${quote}${specifier}${quote};\n${indent}const ${local} = muiIconComponent(${raw});`;
    },
  );
  if (!rewrote) {
    return code;
  }

  const helperImport = `import { muiIconComponent } from ${JSON.stringify(helperSpecifier)};\n`;
  if (next.includes(helperImport)) {
    return next;
  }
  return helperImport + next;
}
