/* Web Worker: loads the wasm module once, analyzes ArrayBuffers. */
import init, { analyze_elf, version } from './pkg/r2brief_core.js';

let ready = null;

async function ensure() {
  if (!ready) {
    ready = init().then(() => version());
  }
  return ready;
}

self.onmessage = async (ev) => {
  const msg = ev.data || {};
  try {
    if (msg.type === 'init') {
      const v = await ensure();
      self.postMessage({ type: 'ready', version: v });
      return;
    }
    if (msg.type === 'analyze') {
      await ensure();
      const { name, bytes } = msg;
      const json = analyze_elf(name, new Uint8Array(bytes));
      self.postMessage({ type: 'result', name, report: JSON.parse(json) });
      return;
    }
    self.postMessage({ type: 'error', error: `unknown message ${msg.type}` });
  } catch (err) {
    self.postMessage({ type: 'error', error: String(err && err.message ? err.message : err) });
  }
};
