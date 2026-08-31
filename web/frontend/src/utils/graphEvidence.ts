import type { ExplorerGraphEdge, ExplorerGraphNode } from '../types';

export type GraphEvidenceMode = 'findings' | 'journey';

export function buildGraphEvidencePrompt(
  node: ExplorerGraphNode,
  mode: GraphEvidenceMode,
  incidentEdges: ExplorerGraphEdge[] = [],
): string {
  const mapLabel = mode === 'findings' ? 'evidence' : 'journey';
  const addressLine = node.address ? `Address / offset: ${node.address}\n` : '';
  const sourceLine = node.source ? `Node source: ${node.source}\n` : '';
  const actorLine = node.actor ? `Actor: ${node.actor}\n` : '';
  const relationLines = incidentEdges.slice(0, 12).map((edge) => {
    const tool = edge.source_tool ? ` via ${edge.source_tool}` : '';
    return `- ${edge.source} --${edge.kind}--> ${edge.target}${tool}`;
  });
  const relations = relationLines.length > 0
    ? relationLines.join('\n')
    : '- No adjacent relationship was supplied.';

  return `Review this ${mapLabel} map node as a bounded evidence item, not as a finding.

Node ID: ${node.id}
Kind: ${node.kind}
Label: ${node.label}
${addressLine}${sourceLine}${actorLine}Adjacent relationships:
${relations}

Properties:
\`\`\`json
${JSON.stringify(node.properties ?? {}, null, 2).slice(0, 2500)}
\`\`\`

Evidence rules:
- An import proves availability, not that the function ran or is reachable.
- A string proves bytes were present, not attacker control, network exposure, or runtime behavior.
- A detector match is a triage lead, not proof of a vulnerability or malicious intent.
- Do not infer runtime behavior, exploitability, or malicious activity unless runtime evidence above establishes it.
- Label any interpretation beyond the supplied evidence as proposed.

Answer with: (1) facts supported by this node and its supplied relationships, (2) explicit evidence limits and unknowns, and (3) one narrow verification step.`;
}
