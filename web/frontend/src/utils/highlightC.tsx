import type { ReactNode } from 'react';

/**
 * Minimal C syntax highlighter that returns React nodes.
 *
 * Decompiler output comes from the analyzed (untrusted) binary, so it must never
 * be turned into HTML. Every piece of source text is emitted as a React text node,
 * which React escapes; only the (constant) colors reach a `style` prop.
 */

export interface CHighlightColors {
  keyword: string;
  type: string;
  string: string;
  number: string;
  comment: string;
}

export const cHighlightColors = (isDark: boolean): CHighlightColors => ({
  keyword: isDark ? '#c678dd' : '#a626a4',
  type: isDark ? '#e5c07b' : '#c18401',
  string: isDark ? '#98c379' : '#50a14f',
  number: isDark ? '#d19a66' : '#986801',
  comment: isDark ? '#5c6370' : '#a0a1a7',
});

const KEYWORDS = new Set([
  'if', 'else', 'while', 'for', 'return', 'break', 'continue', 'switch', 'case', 'default',
  'do', 'goto', 'sizeof', 'typedef', 'struct', 'union', 'enum', 'const', 'static', 'extern',
  'register', 'volatile',
]);

const TYPES = new Set([
  'void', 'int', 'char', 'short', 'long', 'float', 'double', 'unsigned', 'signed', 'uint8_t',
  'uint16_t', 'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t', 'size_t',
  'bool', 'BOOL', 'DWORD', 'WORD', 'BYTE',
]);

// 1: comment, 2: string/char literal, 3: number, 4: identifier
const TOKEN_RE =
  /(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|("(?:[^"\\]|\\[\s\S])*"|'(?:[^'\\]|\\[\s\S])*')|\b(0x[0-9a-fA-F]+|\d+)\b|\b([A-Za-z_][A-Za-z0-9_]*)\b/g;

export const highlightCCode = (code: string, colors: CHighlightColors): ReactNode[] => {
  const nodes: ReactNode[] = [];
  let last = 0;
  let key = 0;

  const push = (text: string, style?: { color: string; fontWeight?: 'bold' }) => {
    if (!text) {
      return;
    }
    nodes.push(
      style ? (
        <span key={key++} style={style}>
          {text}
        </span>
      ) : (
        text
      ),
    );
  };

  for (const match of code.matchAll(TOKEN_RE)) {
    const [text, comment, literal, number, ident] = match;
    const index = match.index ?? 0;
    push(code.slice(last, index));
    last = index + text.length;

    if (comment) {
      push(text, { color: colors.comment });
    } else if (literal) {
      push(text, { color: colors.string });
    } else if (number) {
      push(text, { color: colors.number });
    } else if (ident && KEYWORDS.has(ident)) {
      push(text, { color: colors.keyword, fontWeight: 'bold' });
    } else if (ident && TYPES.has(ident)) {
      push(text, { color: colors.type });
    } else {
      push(text);
    }
  }
  push(code.slice(last));
  return nodes;
};
