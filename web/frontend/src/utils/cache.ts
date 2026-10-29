const CACHE_PREFIX = 'r2b-cache-';
const MAX_CACHE_SIZE = 10;
const CACHE_TTL_MS = 30 * 60 * 1000;

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

interface CacheIndex {
  keys: string[];
  lastUpdated: number;
}

function getCacheIndex(): CacheIndex {
  try {
    const indexStr = sessionStorage.getItem(`${CACHE_PREFIX}index`);
    if (indexStr) {
      return JSON.parse(indexStr);
    }
  } catch {
    // Ignore parse errors
  }
  return { keys: [], lastUpdated: Date.now() };
}

function setCacheIndex(index: CacheIndex): void {
  try {
    sessionStorage.setItem(`${CACHE_PREFIX}index`, JSON.stringify(index));
  } catch {
    // Ignore storage errors
  }
}

function evictIfNeeded(index: CacheIndex): void {
  while (index.keys.length >= MAX_CACHE_SIZE) {
    const oldestKey = index.keys.shift();
    if (oldestKey) {
      sessionStorage.removeItem(`${CACHE_PREFIX}${oldestKey}`);
    }
  }
}

export function getFromCache<T>(key: string): T | null {
  try {
    const entryStr = sessionStorage.getItem(`${CACHE_PREFIX}${key}`);
    if (!entryStr) return null;

    const entry: CacheEntry<T> = JSON.parse(entryStr);

    if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
      sessionStorage.removeItem(`${CACHE_PREFIX}${key}`);
      return null;
    }

    return entry.data;
  } catch {
    return null;
  }
}

export function setInCache<T>(key: string, data: T): void {
  try {
    const index = getCacheIndex();

    const existingIndex = index.keys.indexOf(key);
    if (existingIndex >= 0) {
      index.keys.splice(existingIndex, 1);
    }

    evictIfNeeded(index);

    const entry: CacheEntry<T> = {
      data,
      timestamp: Date.now(),
    };

    sessionStorage.setItem(`${CACHE_PREFIX}${key}`, JSON.stringify(entry));
    index.keys.push(key);
    index.lastUpdated = Date.now();
    setCacheIndex(index);
  } catch {
    // Ignore storage errors (quota exceeded, etc.)
  }
}

export function removeFromCache(key: string): void {
  try {
    sessionStorage.removeItem(`${CACHE_PREFIX}${key}`);
    const index = getCacheIndex();
    const i = index.keys.indexOf(key);
    if (i >= 0) {
      index.keys.splice(i, 1);
      setCacheIndex(index);
    }
  } catch {
    // Ignore errors
  }
}

export function clearCache(): void {
  try {
    const index = getCacheIndex();
    for (const key of index.keys) {
      sessionStorage.removeItem(`${CACHE_PREFIX}${key}`);
    }
    sessionStorage.removeItem(`${CACHE_PREFIX}index`);
  } catch {
    // Ignore errors
  }
}

export const CacheKeys = {
  analysisResult: (sessionId: string) => `analysis-${sessionId}`,
  sessionMessages: (sessionId: string) => `messages-${sessionId}`,
  functionNames: (sessionId: string) => `funcnames-${sessionId}`,
  annotations: (sessionId: string) => `annotations-${sessionId}`,
  events: (sessionId: string) => `events-${sessionId}`,
  graphs: (sessionId: string) => `graphs-${sessionId}`,
};
