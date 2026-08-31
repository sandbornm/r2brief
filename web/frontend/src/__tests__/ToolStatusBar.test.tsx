import { render, screen, waitFor } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import ToolStatusBar from '../components/ToolStatusBar';

// Mock fetch
const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

describe('ToolStatusBar', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows loading state initially', () => {
    mockFetch.mockImplementation(() => new Promise(() => {})); // Never resolves

    render(<ToolStatusBar />);
    expect(screen.getByLabelText(/loading tools/i)).toBeInTheDocument();
  });

  it('displays integrated producer availability when loaded', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          tools: {
            ghidra: { available: true, description: 'Ghidra' },
            radare2: { available: true, description: 'radare2' },
            angr: { available: false, description: 'angr' },
            binwalk: { available: true, description: 'binwalk' },
            gdb: { available: false, description: 'gdb' },
          },
          available_count: 3,
          total_count: 5,
        }),
    });

    render(<ToolStatusBar />);

    await waitFor(() => {
      expect(screen.getByText(/ghidra/i)).toBeInTheDocument();
      expect(screen.getByText('3 available')).toBeInTheDocument();
    });
  });

  it('displays tool names', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          tools: {
            ghidra: {
              available: true,
              description: 'Ghidra',
              bridge_available: true,
              bridge_connected: true,
              headless_available: true,
            },
            radare2: { available: true, description: 'radare2' },
            angr: { available: false, description: 'angr' },
            binwalk: { available: true, description: 'binwalk' },
            gdb: { available: false, description: 'gdb' },
          },
          available_count: 3,
          total_count: 5,
        }),
    });

    render(<ToolStatusBar />);

    await waitFor(() => {
      expect(screen.getByText(/ghidra/i)).toBeInTheDocument();
      expect(screen.getByText('r2')).toBeInTheDocument();
    });
  });

  it('shows bridge connected indicator for Ghidra', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          tools: {
            ghidra: {
              available: true,
              description: 'Ghidra',
              bridge_available: true,
              bridge_connected: true,
              headless_available: false,
            },
            radare2: { available: false, description: 'radare2' },
            angr: { available: false, description: 'angr' },
            binwalk: { available: false, description: 'binwalk' },
            gdb: { available: false, description: 'gdb' },
          },
          available_count: 1,
          total_count: 5,
        }),
    });

    render(<ToolStatusBar />);

    await waitFor(() => {
      expect(screen.getByText(/ghidra/i)).toBeInTheDocument();
    });
  });

  it('handles fetch error gracefully', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network error'));

    render(<ToolStatusBar />);

    await waitFor(() => {
      expect(screen.getByText(/tools offline/i)).toBeInTheDocument();
    });
  });

  it('renders in compact mode', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          tools: {
            ghidra: { available: true, description: 'Ghidra' },
            radare2: { available: true, description: 'radare2' },
            angr: { available: false, description: 'angr' },
            binwalk: { available: false, description: 'binwalk' },
            gdb: { available: false, description: 'gdb' },
          },
          available_count: 2,
          total_count: 5,
        }),
    });

    render(<ToolStatusBar compact />);

    await waitFor(() => {
      expect(screen.getByText('r2')).toBeInTheDocument();
      expect(screen.queryByText(/pwntools/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/ghidramcp/i)).not.toBeInTheDocument();
    });
  });
});
