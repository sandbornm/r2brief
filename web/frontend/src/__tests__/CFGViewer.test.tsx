import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';
import CFGViewer from '../components/CFGViewer';
import { ActivityProvider } from '../contexts/ActivityContext';

const fetchMock = vi.fn();

const functionNamesPayload = {
  function_names: [
    {
      id: 'fn-1',
      address: '0x401000',
      originalName: 'sub_401000',
      displayName: 'http_auth',
      reasoning: 'calls strcmp on a login path',
      confidence: 0.8,
      source: 'llm',
      status: 'proposed',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    },
  ],
};

describe('CFGViewer proposed names', () => {
  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockImplementation((url: string, init?: RequestInit) => {
      if (String(url).endsWith('/function-names') && (!init || init.method === 'GET')) {
        return Promise.resolve(
          new Response(JSON.stringify(functionNamesPayload), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        );
      }
      return Promise.resolve(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('keeps the original name canonical and lets a human accept the proposal', async () => {
    const user = userEvent.setup();
    render(
      <ActivityProvider>
        <CFGViewer
          nodes={[]}
          edges={[]}
          sessionId="session-1"
          functions={[
            {
              name: 'sub_401000',
              offset: '0x401000',
              size: 32,
              blocks: [{ offset: '0x401000', size: 32, disassembly: [{ addr: '0x401000', opcode: 'ret' }] }],
            },
          ]}
        />
      </ActivityProvider>,
    );

    const accept = await screen.findByRole('button', { name: /accept proposed name http_auth/i });
    expect(screen.getByText(/~http_auth/)).toBeInTheDocument();

    await user.click(accept);

    await waitFor(() => {
      const posts = fetchMock.mock.calls.filter(([, init]) => init && init.method === 'POST');
      expect(posts.length).toBeGreaterThan(0);
      const body = JSON.parse(String(posts[0][1].body));
      expect(body.status).toBe('accepted');
      expect(body.displayName).toBe('http_auth');
    });
  });
});
