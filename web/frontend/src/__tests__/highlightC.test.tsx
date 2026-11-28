import { render } from '@testing-library/react';
import DecompilerPanel from '../components/DecompilerPanel';
import type { GhidraData } from '../types';
import { cHighlightColors, highlightCCode } from '../utils/highlightC';

const colors = cHighlightColors(false);

const renderHighlighted = (code: string) => {
  const { container } = render(<pre>{highlightCCode(code, colors)}</pre>);
  return container;
};

describe('highlightCCode', () => {
  it('keeps the source text intact', () => {
    const code = 'int main(void) {\n  // note 42\n  return 0x1F + 7; /* done */\n}\n';
    expect(renderHighlighted(code).textContent).toBe(code);
  });

  it('colors keywords, types, numbers, strings and comments', () => {
    const container = renderHighlighted('int x = 5; return "s"; // c');
    const spans = Array.from(container.querySelectorAll('span')).map((s) => [s.textContent, s.style.color]);
    expect(spans).toEqual(
      expect.arrayContaining([
        ['int', 'rgb(193, 132, 1)'],
        ['5', 'rgb(152, 104, 1)'],
        ['return', 'rgb(166, 38, 164)'],
        ['"s"', 'rgb(80, 161, 79)'],
        ['// c', 'rgb(160, 161, 167)'],
      ]),
    );
  });

  it('never creates elements or attributes from hostile decompiler output', () => {
    const hostile = [
      '// " onmouseover=alert(1) x="',
      "// ' onerror=alert(2) '",
      '<img src=x onerror=alert(3)>',
      'char *s = "</span><script>alert(4)</script>";',
      '/* <svg onload=alert(5)> */',
      'int 986801 = 0x986801; return;',
    ].join('\n');
    const container = renderHighlighted(hostile);

    expect(container.textContent).toBe(hostile);
    expect(container.querySelector('img, script, svg')).toBeNull();
    container.querySelectorAll('*').forEach((el) => {
      const attrs = Array.from(el.attributes).map((a) => a.name);
      expect(attrs.every((name) => name === 'style')).toBe(true);
    });
  });
});

describe('DecompilerPanel rendering', () => {
  it('renders decompiled C as text, not HTML', () => {
    const payload = '<img src=x onerror=alert(1)>';
    const data: GhidraData = {
      mode: 'headless',
      binary: '/tmp/sample.elf',
      decompiled_count: 1,
      type_count: 0,
      types: [],
      decompiled: [
        {
          name: 'evil',
          address: '0x1000',
          signature: 'void evil(void)',
          decompiled_c: `// ${payload}\nvoid evil(void) {}`,
          parameters: [],
          return_type: 'void',
          calling_convention: null,
        },
      ],
    };
    const { container } = render(<DecompilerPanel data={data} />);
    expect(container.querySelector('img')).toBeNull();
    expect(container.textContent).toContain(payload);
  });
});
