export type TrajectoryNodeType =
  | 'session_start'
  | 'binary_upload'
  | 'analysis_start'
  | 'analysis_complete'
  | 'view_function'
  | 'view_disasm'
  | 'view_cfg'
  | 'view_decompiled'
  | 'view_strings'
  | 'view_security'
  | 'view_dwarf'
  | 'view_dynamic'
  | 'select_code'
  | 'annotate'
  | 'ask_question'
  | 'receive_answer'
  | 'rename_function'
  | 'navigate_address';

export interface TrajectoryNode {
  id: string;
  type: TrajectoryNodeType;
  timestamp: number;
  duration_ms?: number;
  data: TrajectoryNodeData;
}

export interface TrajectoryNodeData {
  function_name?: string;
  function_address?: string;

  address?: string;

  code_snippet?: string;
  line_count?: number;

  question?: string;
  question_topic?: string;
  answer_preview?: string;

  tools_used?: string[];
  binary_name?: string;
  architecture?: string;

  note?: string;

  from_tab?: string;
  to_tab?: string;

  [key: string]: unknown;
}

export interface TrajectoryEdge {
  from: string;
  to: string;
  type: 'sequence' | 'reference' | 'follow_up';
}

export interface Trajectory {
  id: string;
  session_id: string;
  created_at: string;
  updated_at: string;
  nodes: TrajectoryNode[];
  edges: TrajectoryEdge[];

  stats: TrajectoryStats;
}

export interface TrajectoryStats {
  total_actions: number;
  functions_viewed: number;
  questions_asked: number;
  annotations_made: number;
  time_on_disasm_ms: number;
  time_on_cfg_ms: number;
  time_on_chat_ms: number;
  unique_addresses_visited: number;
}

export interface TrajectorySnapshot {
  current_view: string;
  current_function?: string;
  current_address?: string;

  session_duration_s: number;
  actions_count: number;
  functions_explored: string[];
  addresses_visited: string[];

  recent_actions: string[];

  questions: { q: string; answered: boolean }[];

  focus_area?: 'functions' | 'strings' | 'security' | 'dynamic' | 'exploration';
  depth_level: 'overview' | 'investigating' | 'deep_dive';
}

let nodeCounter = 0;
const generateNodeId = (): string => {
  nodeCounter++;
  return `n${nodeCounter}_${Date.now().toString(36)}`;
};

export const createTrajectory = (sessionId: string): Trajectory => ({
  id: `traj_${Date.now().toString(36)}`,
  session_id: sessionId,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  nodes: [],
  edges: [],
  stats: {
    total_actions: 0,
    functions_viewed: 0,
    questions_asked: 0,
    annotations_made: 0,
    time_on_disasm_ms: 0,
    time_on_cfg_ms: 0,
    time_on_chat_ms: 0,
    unique_addresses_visited: 0,
  },
});

export const addNode = (
  trajectory: Trajectory,
  type: TrajectoryNodeType,
  data: TrajectoryNodeData = {}
): { trajectory: Trajectory; nodeId: string } => {
  const nodeId = generateNodeId();
  const node: TrajectoryNode = {
    id: nodeId,
    type,
    timestamp: Date.now(),
    data,
  };

  const lastNode = trajectory.nodes[trajectory.nodes.length - 1];
  const edges = [...trajectory.edges];

  if (lastNode) {
    edges.push({
      from: lastNode.id,
      to: nodeId,
      type: 'sequence',
    });

    lastNode.duration_ms = node.timestamp - lastNode.timestamp;
  }

  const stats = { ...trajectory.stats };
  stats.total_actions++;

  if (type === 'view_function') {
    stats.functions_viewed++;
  } else if (type === 'ask_question') {
    stats.questions_asked++;
  } else if (type === 'annotate') {
    stats.annotations_made++;
  } else if (type === 'navigate_address' && data.address) {
    stats.unique_addresses_visited++;
  }

  return {
    trajectory: {
      ...trajectory,
      nodes: [...trajectory.nodes, node],
      edges,
      stats,
      updated_at: new Date().toISOString(),
    },
    nodeId,
  };
};

export const updateTabTimes = (trajectory: Trajectory): Trajectory => {
  const stats = { ...trajectory.stats };

  for (const node of trajectory.nodes) {
    if (!node.duration_ms) continue;

    if (node.type === 'view_disasm') {
      stats.time_on_disasm_ms += node.duration_ms;
    } else if (node.type === 'view_cfg') {
      stats.time_on_cfg_ms += node.duration_ms;
    } else if (node.type === 'ask_question' || node.type === 'receive_answer') {
      stats.time_on_chat_ms += node.duration_ms;
    }
  }

  return { ...trajectory, stats };
};

export const createSnapshot = (
  trajectory: Trajectory,
  currentView: string,
  maxRecentActions: number = 8
): TrajectorySnapshot => {
  const now = Date.now();
  const startTime = trajectory.nodes[0]?.timestamp || now;
  const sessionDuration = Math.floor((now - startTime) / 1000);

  const functionsExplored = new Set<string>();
  const addressesVisited = new Set<string>();
  const questions: { q: string; answered: boolean }[] = [];
  let currentFunction: string | undefined;
  let currentAddress: string | undefined;

  for (const node of trajectory.nodes) {
    if (node.data.function_name) {
      functionsExplored.add(node.data.function_name);
      if (node.type === 'view_function') {
        currentFunction = node.data.function_name;
      }
    }
    if (node.data.address) {
      addressesVisited.add(node.data.address);
      if (node.type === 'navigate_address') {
        currentAddress = node.data.address;
      }
    }
    if (node.type === 'ask_question' && node.data.question) {
      questions.push({
        q: truncate(node.data.question, 50),
        answered: true,
      });
    }
  }

  const recentNodes = trajectory.nodes.slice(-maxRecentActions);
  const recentActions = recentNodes.map(formatNodeAction);

  const focusArea = determineFocusArea(trajectory);

  const depthLevel = determineDepthLevel(trajectory);

  return {
    current_view: currentView,
    current_function: currentFunction,
    current_address: currentAddress,
    session_duration_s: sessionDuration,
    actions_count: trajectory.stats.total_actions,
    functions_explored: Array.from(functionsExplored).slice(-10),
    addresses_visited: Array.from(addressesVisited).slice(-10),
    recent_actions: recentActions,
    questions: questions.slice(-5),
    focus_area: focusArea,
    depth_level: depthLevel,
  };
};

export const serializeSnapshot = (snapshot: TrajectorySnapshot): string => {
  const lines: string[] = [];

  lines.push(`[User Context]`);
  lines.push(`View: ${snapshot.current_view}`);

  if (snapshot.current_function) {
    lines.push(`Function: ${snapshot.current_function}`);
  }
  if (snapshot.current_address) {
    lines.push(`Address: ${snapshot.current_address}`);
  }

  lines.push(`Session: ${formatDuration(snapshot.session_duration_s)}, ${snapshot.actions_count} actions`);
  lines.push(`Depth: ${snapshot.depth_level}`);

  if (snapshot.focus_area) {
    lines.push(`Focus: ${snapshot.focus_area}`);
  }

  if (snapshot.functions_explored.length > 0) {
    lines.push(`Explored: ${snapshot.functions_explored.join(', ')}`);
  }

  if (snapshot.recent_actions.length > 0) {
    lines.push(`\nRecent:`);
    for (const action of snapshot.recent_actions) {
      lines.push(`  - ${action}`);
    }
  }

  if (snapshot.questions.length > 0) {
    lines.push(`\nAsked:`);
    for (const q of snapshot.questions) {
      lines.push(`  - ${q.q}`);
    }
  }

  return lines.join('\n');
};

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}

function formatNodeAction(node: TrajectoryNode): string {
  const ago = formatTimeAgo(node.timestamp);

  switch (node.type) {
    case 'view_function':
      return `${ago}: viewed ${node.data.function_name || 'function'}`;
    case 'view_disasm':
      return `${ago}: viewed disassembly`;
    case 'view_cfg':
      return `${ago}: viewed CFG`;
    case 'view_decompiled':
      return `${ago}: viewed decompiled code`;
    case 'view_strings':
      return `${ago}: browsed strings`;
    case 'view_security':
      return `${ago}: checked security features`;
    case 'ask_question':
      return `${ago}: asked "${truncate(node.data.question || 'question', 30)}"`;
    case 'select_code':
      return `${ago}: selected ${node.data.line_count || '?'} lines`;
    case 'annotate':
      return `${ago}: annotated ${node.data.address || 'code'}`;
    case 'navigate_address':
      return `${ago}: jumped to ${node.data.address}`;
    case 'rename_function':
      return `${ago}: renamed ${node.data.function_name}`;
    default:
      return `${ago}: ${node.type.replace(/_/g, ' ')}`;
  }
}

function formatTimeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 10) return 'now';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h`;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

function determineFocusArea(trajectory: Trajectory): TrajectorySnapshot['focus_area'] {
  const recent = trajectory.nodes.slice(-10);
  const counts: Record<string, number> = {
    functions: 0,
    strings: 0,
    security: 0,
    dynamic: 0,
    exploration: 0,
  };

  for (const node of recent) {
    if (node.type === 'view_function' || node.type === 'view_cfg' || node.type === 'view_decompiled') {
      counts.functions++;
    } else if (node.type === 'view_strings') {
      counts.strings++;
    } else if (node.type === 'view_security') {
      counts.security++;
    } else if (node.type === 'view_dynamic') {
      counts.dynamic++;
    } else {
      counts.exploration++;
    }
  }

  const max = Math.max(...Object.values(counts));
  if (max === 0) return undefined;

  for (const [area, count] of Object.entries(counts)) {
    if (count === max && count >= 3) {
      return area as TrajectorySnapshot['focus_area'];
    }
  }

  return 'exploration';
}

function determineDepthLevel(trajectory: Trajectory): TrajectorySnapshot['depth_level'] {
  const stats = trajectory.stats;

  if (stats.functions_viewed >= 5 || stats.annotations_made >= 2 || stats.questions_asked >= 3) {
    return 'deep_dive';
  }

  if (stats.functions_viewed >= 2 || stats.questions_asked >= 1) {
    return 'investigating';
  }

  return 'overview';
}

export default {
  createTrajectory,
  addNode,
  updateTabTimes,
  createSnapshot,
  serializeSnapshot,
};
