import { pathToFileURL } from 'node:url';

// jsdom 30 engines. setup_frontend.sh and the toolchain tests both use this.
export const FRONTEND_NODE_RANGE = '^22.22.2 || ^24.15.0 || >=26.0.0';

function parse(version) {
  const core = String(version).trim().replace(/^v/, '').split('-', 1)[0];
  const parts = core.split('.').map((piece) => Number(piece));
  while (parts.length < 3) {
    parts.push(0);
  }
  return parts.slice(0, 3);
}

function bump(version) {
  return [version[0], version[1], version[2] + 1];
}

function compare(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) {
      return left[index] < right[index] ? -1 : 1;
    }
  }
  return 0;
}

function satisfiesAtom(version, atom) {
  const current = parse(version);
  if (atom.startsWith('>=')) {
    return compare(current, parse(atom.slice(2))) >= 0;
  }
  if (atom.startsWith('<=')) {
    return compare(current, parse(atom.slice(2))) <= 0;
  }
  if (atom.startsWith('>')) {
    return compare(current, parse(atom.slice(1))) > 0;
  }
  if (atom.startsWith('<')) {
    return compare(current, parse(atom.slice(1))) < 0;
  }
  if (atom.startsWith('^')) {
    const base = parse(atom.slice(1));
    const upper = base[0] > 0 ? [base[0] + 1, 0, 0] : [0, base[1] + 1, 0];
    return compare(current, base) >= 0 && compare(current, upper) < 0;
  }
  if (atom.startsWith('~')) {
    const base = parse(atom.slice(1));
    const upper = [base[0], base[1] + 1, 0];
    return compare(current, base) >= 0 && compare(current, upper) < 0;
  }
  return compare(current, parse(atom)) === 0;
}

export function nodeSatisfies(version, rangeSpec = FRONTEND_NODE_RANGE) {
  return rangeSpec.split('||').some((alternative) => {
    const atoms = alternative.trim().split(/\s+/).filter(Boolean);
    return atoms.length > 0 && atoms.every((atom) => satisfiesAtom(version, atom));
  });
}

const isDirectRun = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectRun) {
  const version = process.argv[2] ?? process.versions.node;
  if (!nodeSatisfies(version)) {
    console.error(
      `Node.js ${version} does not satisfy ${FRONTEND_NODE_RANGE}.`,
    );
    process.exit(1);
  }
}
