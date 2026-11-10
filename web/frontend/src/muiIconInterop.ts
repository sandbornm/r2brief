function isRenderableComponent(value: unknown): boolean {
  return typeof value === 'function' || (value != null && typeof value === 'object' && '$$typeof' in value);
}

/**
 * Vite's dev prebundle can hand an MUI icon to React 19 as
 * `{ default: Component }`, and a namespace import nests that one level
 * further. `createSvgIcon` returns a forwardRef object, so the component
 * is not always a function. Production builds already receive the
 * component, and this leaves that shape alone.
 */
export function muiIconComponent(imported: unknown): unknown {
  let current = imported;
  const seen = new Set<unknown>();
  while (
    current != null &&
    typeof current === 'object' &&
    !isRenderableComponent(current) &&
    'default' in current &&
    !seen.has(current)
  ) {
    seen.add(current);
    current = current.default;
  }
  return current;
}
