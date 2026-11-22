import { render, screen } from '@testing-library/react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { describe, expect, it } from 'vitest';
import MarkdownRenderer from '../components/MarkdownRenderer';

function renderMarkdown(content: string, props: { disassembly?: string } = {}) {
  return render(
    <ThemeProvider theme={createTheme()}>
      <MarkdownRenderer content={content} {...props} />
    </ThemeProvider>,
  );
}

describe('MarkdownRenderer', () => {
  it('renders headings, links, inline code, and fenced code', () => {
    renderMarkdown(`# Findings

See [the docs](https://example.com/docs).

Use \`mov r0, r1\` or:

\`\`\`asm
mov r0, r1
\`\`\`
`);

    expect(screen.getByRole('heading', { level: 1, name: 'Findings' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'the docs' })).toHaveAttribute('href', 'https://example.com/docs');
    expect(screen.getAllByText('mov r0, r1').length).toBeGreaterThan(0);
    expect(screen.getByText('ARM')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    expect(screen.getByTestId('ContentCopyIcon')).toBeInTheDocument();
  });

  it('renders remark-gfm tables', () => {
    renderMarkdown(`| Register | Value |
| --- | --- |
| r0 | 1 |
`);

    expect(screen.getByRole('table')).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Register' })).toBeInTheDocument();
    expect(screen.getByRole('cell', { name: 'r0' })).toBeInTheDocument();
  });

  it('cites addresses when disassembly is supplied', () => {
    renderMarkdown('Branch to 0x401000 next.', {
      disassembly: '0x401000 mov r0, r1',
    });

    const address = screen.getByText('0x401000');
    expect(address.tagName).toBe('SPAN');
    expect(address.closest('p')).toHaveTextContent('Branch to 0x401000 next.');
  });
});
