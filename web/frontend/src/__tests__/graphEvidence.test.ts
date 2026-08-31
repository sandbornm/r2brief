import { describe, expect, it } from 'vitest';
import { buildGraphEvidencePrompt } from '../utils/graphEvidence';

describe('buildGraphEvidencePrompt', () => {
  it('keeps imports and strings inside explicit evidence limits', () => {
    const prompt = buildGraphEvidencePrompt(
      {
        id: 'import:execl',
        kind: 'import',
        label: 'execl',
        source: 'radare2',
        properties: { bind: 'GLOBAL' },
      },
      'findings',
      [
        {
          id: 'edge:imports',
          kind: 'imports',
          source: 'binary:root',
          target: 'import:execl',
          source_tool: 'radare2',
          properties: {},
        },
      ],
    );

    expect(prompt).toContain('Review this evidence map node');
    expect(prompt).toContain('bounded evidence item, not as a finding');
    expect(prompt).toContain('An import proves availability, not that the function ran or is reachable.');
    expect(prompt).toContain('Do not infer runtime behavior, exploitability, or malicious activity');
    expect(prompt).toContain('explicit evidence limits and unknowns');
    expect(prompt).toContain('binary:root --imports--> import:execl via radare2');
  });
});
