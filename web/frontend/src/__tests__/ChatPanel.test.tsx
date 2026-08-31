import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ChatPanel from '../components/ChatPanel';
import type { ChatMessageItem, ChatSessionSummary } from '../types';

describe('ChatPanel', () => {
  const session: ChatSessionSummary = {
    session_id: 'session-1',
    binary_path: '/tmp/a.out',
    title: 'Sample binary',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    message_count: 0,
  };

  const messages: ChatMessageItem[] = [
    {
      message_id: 'm1',
      session_id: 'session-1',
      role: 'system',
      content: 'Analysis completed',
      attachments: [],
      created_at: new Date().toISOString(),
    },
  ];

  it('submits user input via onSend callback', async () => {
    const user = userEvent.setup();
    const handleSend = vi.fn().mockResolvedValue(undefined);

    render(
      <ChatPanel
        session={session}
        messages={messages}
        onSend={handleSend}
      />,
    );

    await user.type(screen.getByPlaceholderText(/ask about the binary/i), 'What does main do?');
    await user.click(screen.getByRole('button', { name: /send/i }));

    expect(handleSend).toHaveBeenCalledWith('What does main do?', { callLLM: true });
  });

  it('shows cited and uncited chips on an assistant reply', () => {
    render(
      <ChatPanel
        session={session}
        messages={[
          {
            message_id: 'm2',
            session_id: 'session-1',
            role: 'assistant',
            content: '- strcpy is attacker-controlled [tool=radare2 addr=0x7a8]',
            attachments: [
              {
                type: 'llm_response_meta',
                provider: 'openrouter',
                cited_claims: {
                  claims: [{ text: 'strcpy is attacker-controlled', cites: [{ tool: 'radare2' }] }],
                  uncited: ['ungrounded claim'],
                  proposed: ['proposed name http_auth'],
                  grounded: false,
                },
              },
            ],
            created_at: new Date().toISOString(),
          },
        ]}
        onSend={vi.fn()}
      />,
    );

    expect(screen.getByText('via openrouter')).toBeInTheDocument();
    expect(screen.getByText(/1 cited/i)).toBeInTheDocument();
    expect(screen.getByText(/1 uncited — ungrounded/i)).toBeInTheDocument();
    expect(screen.getByText(/1 proposed name\/type/i)).toBeInTheDocument();
  });

  it('shows empty state when no session', () => {
    render(
      <ChatPanel
        session={null}
        messages={[]}
        onSend={vi.fn()}
      />,
    );

    expect(screen.getByText(/no session selected/i)).toBeInTheDocument();
  });
});
