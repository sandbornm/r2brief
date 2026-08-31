import '@testing-library/jest-dom/vitest';

// Mock scrollIntoView since jsdom doesn't implement it
Element.prototype.scrollIntoView = vi.fn();

// Node >= 25 defines a partial localStorage global without the Storage API.
// Replace missing or partial implementations; leave jsdom/Node 20 alone.
if (
  typeof globalThis.localStorage === 'undefined' ||
  typeof globalThis.localStorage.clear !== 'function' ||
  typeof globalThis.localStorage.getItem !== 'function'
) {
  const store = new Map<string, string>();
  const shim: Storage = {
    get length() { return store.size; },
    clear: () => store.clear(),
    getItem: (key) => (store.has(key) ? store.get(key)! : null),
    key: (index) => Array.from(store.keys())[index] ?? null,
    removeItem: (key) => { store.delete(key); },
    setItem: (key, value) => { store.set(key, String(value)); },
  };
  Object.defineProperty(globalThis, 'localStorage', { value: shim, configurable: true });
}
