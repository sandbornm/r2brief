export type ToolCategory = 'core' | 'firmware' | 'static' | 'dynamic' | 'library' | 'service' | 'ai';

export interface ToolCatalogEntry {
  key: string;
  displayName: string;
  shortName: string;
  category: ToolCategory;
  description: string;
  produces: string;
  priority: number;
  aliases?: string[];
}

// This is intentionally an integration catalog, not an environment inventory.
// A detected executable belongs here only when r2b schedules it and records its
// output as evidence. Probe-only helpers remain available from `r2b env --json`.
export const TOOL_CATALOG: ToolCatalogEntry[] = [
  {
    key: 'firmware',
    displayName: 'Firmware',
    shortName: 'fw',
    category: 'firmware',
    description: 'Wrapper and embedded-blob inventory.',
    produces: 'Signatures, carve hints',
    priority: 10,
  },
  {
    key: 'binwalk',
    displayName: 'binwalk',
    shortName: 'binwalk',
    category: 'firmware',
    description: 'Signature scan and extract helper.',
    produces: 'FS signatures',
    priority: 20,
  },
  {
    key: 'binwalk3',
    displayName: 'binwalk3',
    shortName: 'bw3',
    category: 'firmware',
    description: 'Bounded extractor selected for container subjects.',
    produces: 'Extracted artifacts',
    priority: 25,
  },
  {
    key: 'unblob',
    displayName: 'unblob',
    shortName: 'unblob',
    category: 'firmware',
    description: 'Bounded recursive extractor selected for container subjects.',
    produces: 'Extracted artifacts',
    priority: 26,
  },
  {
    key: 'libmagic',
    displayName: 'libmagic',
    shortName: 'magic',
    category: 'core',
    description: 'File-type magic.',
    produces: 'Type / MIME',
    priority: 40,
    aliases: ['identification'],
  },
  {
    key: 'radare2',
    displayName: 'radare2',
    shortName: 'r2',
    category: 'static',
    description: 'Disassembly, functions, imports.',
    produces: 'Listing + metadata',
    priority: 50,
    aliases: ['r2'],
  },
  {
    key: 'capstone',
    displayName: 'Capstone',
    shortName: 'cap',
    category: 'library',
    description: 'Instruction decoder.',
    produces: 'Operands',
    priority: 60,
  },
  {
    key: 'dwarf',
    displayName: 'DWARF',
    shortName: 'dwarf',
    category: 'library',
    description: 'Debug symbols and types.',
    produces: 'DWARF',
    priority: 75,
  },
  {
    key: 'angr',
    displayName: 'angr',
    shortName: 'angr',
    category: 'static',
    description: 'Symbolic execution / CFG.',
    produces: 'CFG, paths',
    priority: 100,
  },

  {
    key: 'ghidra',
    displayName: 'Ghidra',
    shortName: 'ghidra',
    category: 'static',
    description: 'Decompiler (headless).',
    produces: 'C-like, xrefs',
    priority: 120,
  },
  {
    key: 'gef',
    displayName: 'GEF/GDB',
    shortName: 'gef',
    category: 'dynamic',
    description: 'GDB traces in Docker.',
    produces: 'Trace, maps',
    priority: 160,
  },
  {
    key: 'frida',
    displayName: 'Frida',
    shortName: 'frida',
    category: 'dynamic',
    description: 'Runtime hooks.',
    produces: 'Modules, hooks',
    priority: 170,
  },
  {
    key: 'ollama',
    displayName: 'Ollama',
    shortName: 'ollama',
    category: 'ai',
    description: 'Local chat models.',
    produces: 'Replies',
    priority: 300,
  },
];

const catalogByKey = new Map<string, ToolCatalogEntry>();

for (const entry of TOOL_CATALOG) {
  catalogByKey.set(entry.key, entry);
  for (const alias of entry.aliases ?? []) {
    catalogByKey.set(alias, entry);
  }
}

export const TOOL_ORDER = TOOL_CATALOG.map((tool) => tool.key);

export const getToolCatalogEntry = (name: string): ToolCatalogEntry | undefined => catalogByKey.get(name);

export const getToolDisplayName = (name: string): string => getToolCatalogEntry(name)?.displayName ?? name;

export const getToolShortName = (name: string): string => getToolCatalogEntry(name)?.shortName ?? name;

export const getToolDescription = (name: string): string => getToolCatalogEntry(name)?.description ?? 'Analysis support';

export const getToolProduces = (name: string): string => getToolCatalogEntry(name)?.produces ?? 'Analysis output';

export const getToolCategory = (name: string): ToolCategory | 'unknown' =>
  getToolCatalogEntry(name)?.category ?? 'unknown';

const getToolPriority = (name: string): number => getToolCatalogEntry(name)?.priority ?? 999;

export const sortToolEntries = <T>(entries: [string, T][]): [string, T][] =>
  [...entries].sort(([left], [right]) => getToolPriority(left) - getToolPriority(right) || left.localeCompare(right));
