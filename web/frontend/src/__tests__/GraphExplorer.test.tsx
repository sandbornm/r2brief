import { fireEvent, render, screen } from '@testing-library/react';
import GraphExplorer from '../components/GraphExplorer';
import type { AnalysisGraphPayload } from '../types';

const graph: AnalysisGraphPayload = {
  schema_version: 'r2b.analysis_graph.v1',
  binary: 'router-firmware.bin',
  generated_at: '2026-01-01T00:00:00Z',
  nodes: [
    { id: 'binary:root', kind: 'binary', label: 'router-firmware.bin', source: 'r2b', properties: {} },
    { id: 'profile:inventory', kind: 'firmware_profile', label: 'Firmware inventory', source: 'firmware', properties: {} },
    {
      id: 'artifact:rootfs',
      kind: 'embedded_artifact',
      label: 'SquashFS rootfs',
      source: 'firmware',
      address: '0x1000',
      properties: { kind: 'squashfs_filesystem', recommended: true },
    },
    { id: 'function:main', kind: 'function', label: 'main', source: 'ghidra_gdb', address: '0x401000', properties: {} },
    { id: 'import:system', kind: 'import', label: 'system', source: 'radare2', properties: {} },
    { id: 'string:admin', kind: 'string', label: 'admin password', source: 'radare2', properties: {} },
    { id: 'tool:angr_mcp', kind: 'tool', label: 'angr_mcp', source: 'r2b', properties: { available: false } },
    { id: 'issue:telnet', kind: 'issue', label: 'Telnet reachable from LAN', source: 'r2b', properties: {} },
  ],
  edges: [
    { id: 'e1', kind: 'has_inventory', source: 'binary:root', target: 'profile:inventory', source_tool: 'firmware', properties: {} },
    { id: 'e2', kind: 'contains_artifact', source: 'binary:root', target: 'artifact:rootfs', source_tool: 'firmware', properties: {} },
    { id: 'e3', kind: 'contains_function', source: 'binary:root', target: 'function:main', source_tool: 'ghidra_gdb', properties: {} },
    { id: 'e4', kind: 'imports', source: 'function:main', target: 'import:system', source_tool: 'radare2', properties: {} },
    { id: 'e5', kind: 'references_string', source: 'function:main', target: 'string:admin', source_tool: 'radare2', properties: {} },
    { id: 'e6', kind: 'has_issue', source: 'string:admin', target: 'issue:telnet', source_tool: 'r2b', properties: {} },
    { id: 'e7', kind: 'candidate_for', source: 'artifact:rootfs', target: 'tool:angr_mcp', source_tool: 'firmware', properties: {} },
    { id: 'e8', kind: 'has_issue', source: 'artifact:rootfs', target: 'issue:telnet', source_tool: 'r2b', properties: {} },
  ],
  summary: {
    node_count: 8,
    edge_count: 8,
    node_kinds: {
      binary: 1,
      firmware_profile: 1,
      embedded_artifact: 1,
      function: 1,
      import: 1,
      string: 1,
      tool: 1,
      issue: 1,
    },
  },
};

describe('GraphExplorer', () => {
  it('starts as a calm segmented map and can focus a segment', () => {
    render(<GraphExplorer analysisGraph={graph} />);

    expect(screen.getByText('Evidence Map')).toBeInTheDocument();
    expect(screen.getByText(/6 areas/i)).toBeInTheDocument();
    expect(screen.getByText(/Calm density/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /calm map density/i })).toHaveAttribute('aria-pressed', 'true');

    fireEvent.click(screen.getByRole('button', { name: /linked map density/i }));
    expect(screen.getByText(/Linked density/i)).toBeInTheDocument();

    fireEvent.click(screen.getByText(/Artifacts 1 \/ 1 pivot/i));
    expect(screen.getByText(/1 nodes and .* links in this segment/i)).toBeInTheDocument();
  });

  it('labels pivots and issues without presenting them as behavior or confirmed findings', () => {
    render(<GraphExplorer analysisGraph={graph} />);

    expect(screen.getByText(/Indicators 2 \/ 2 pivots/i)).toBeInTheDocument();
    expect(screen.getByText(/Issues 1 \/ 1 pivot/i)).toBeInTheDocument();
    expect(screen.queryByText(/^Behavior$/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^Findings$/)).not.toBeInTheDocument();
    expect(screen.queryByText(/confirmed finding/i)).not.toBeInTheDocument();
  });

  it('shows how selected evidence was established', () => {
    render(<GraphExplorer analysisGraph={graph} />);

    fireEvent.click(screen.getByText(/Issues 1 \/ 1 pivot/i));
    fireEvent.click(screen.getAllByText('Telnet reachable from LAN')[0]);

    expect(screen.getByText('Evidence')).toBeInTheDocument();
    expect(screen.getAllByText('analysis issue').length).toBeGreaterThan(0);
    expect(screen.getByText('Established by')).toBeInTheDocument();
    expect(screen.getAllByText('r2b').length).toBeGreaterThan(0);
  });

  it('describes static pivots as literal name and string matches', () => {
    render(<GraphExplorer analysisGraph={graph} />);

    fireEvent.click(screen.getByText(/Indicators 2 \/ 2 pivots/i));

    expect(screen.getByText('import-name match: system')).toBeInTheDocument();
    expect(screen.getByText('string match')).toBeInTheDocument();
    expect(screen.queryByText(/network-facing signal/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/credential or privilege signal/i)).not.toBeInTheDocument();
  });

  it('groups authentication text as string matches rather than credentials', () => {
    const authStrings = ['login prompt', 'auth mode', 'admin role', 'password policy', 'token format']
      .map((label, index) => ({
        id: `string:auth:${index}`,
        kind: 'string',
        label,
        source: 'radare2',
        address: `0x${(0x5000 + index * 16).toString(16)}`,
        properties: {},
      }));
    const authGraph: AnalysisGraphPayload = {
      ...graph,
      nodes: [...graph.nodes, ...authStrings],
      summary: { ...graph.summary, node_count: graph.nodes.length + authStrings.length },
    };

    render(<GraphExplorer analysisGraph={authGraph} />);
    fireEvent.click(screen.getByText(/Indicators 7/));

    expect(screen.getAllByText('Authentication-related string matches').length).toBeGreaterThan(0);
    expect(screen.queryByText(/Credential strings/i)).not.toBeInTheDocument();
  });

  it('folds artifact-DAG kinds into existing map segments', () => {
    const dagGraph: AnalysisGraphPayload = {
      ...graph,
      nodes: [
        ...graph.nodes,
        { id: 'n:elf:httpd', kind: 'elf', label: 'httpd', source: 'binwalk3', address: '0x4d', properties: {} },
        { id: 'n:fs:root', kind: 'filesystem', label: 'squashfs', source: 'binwalk3', address: '0x1000', properties: {} },
        { id: 'n:ep:http', kind: 'endpoint', label: 'http://tplinkdeco.net', source: 'firmware', properties: {} },
      ],
      summary: {
        ...graph.summary,
        node_count: 11,
        node_kinds: {
          ...(graph.summary.node_kinds as Record<string, number>),
          elf: 1,
          filesystem: 1,
          endpoint: 1,
        },
      },
    };
    render(<GraphExplorer analysisGraph={dagGraph} />);
    expect(screen.queryByText(/^Elf$/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^Filesystem$/)).not.toBeInTheDocument();
    expect(screen.getByText(/Code 2/)).toBeInTheDocument();
    expect(screen.getByText(/Artifacts 2/)).toBeInTheDocument();
    expect(screen.getByText(/Indicators 3/)).toBeInTheDocument();
  });
});
