import { render, screen } from '@testing-library/react';
import HexViewer from '../components/HexViewer';

describe('HexViewer', () => {
  it('renders empty state when no data', () => {
    render(<HexViewer data={null} />);
    expect(screen.getByText(/no binary data/i)).toBeInTheDocument();
  });

  it('renders empty state for empty array', () => {
    render(<HexViewer data={[]} />);
    expect(screen.getByText(/no binary data/i)).toBeInTheDocument();
  });

  it('renders hex data from number array', () => {
    const data = [0x48, 0x65, 0x6c, 0x6c, 0x6f];
    render(<HexViewer data={data} />);

    expect(screen.getByText('48')).toBeInTheDocument();
    expect(screen.getByText('65')).toBeInTheDocument();
    expect(screen.getAllByText('6C').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('6F')).toBeInTheDocument();
  });

  it('renders hex data from Uint8Array', () => {
    const data = new Uint8Array([0x41, 0x42, 0x43]);
    render(<HexViewer data={data} />);

    expect(screen.getByText('41')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText('43')).toBeInTheDocument();
  });

  it('displays ASCII representation', () => {
    const data = [0x48, 0x65, 0x6c, 0x6c, 0x6f];
    render(<HexViewer data={data} />);

    expect(screen.getByText('H')).toBeInTheDocument();
    expect(screen.getByText('e')).toBeInTheDocument();
  });

  it('displays dots for non-printable characters', () => {
    const data = [0x00, 0x01, 0x02, 0x41];
    render(<HexViewer data={data} />);

    const dots = screen.getAllByText('.');
    expect(dots.length).toBeGreaterThanOrEqual(3);

    expect(screen.getByText('A')).toBeInTheDocument();
  });

  it('respects baseAddress prop', () => {
    const data = [0x41, 0x42];
    render(<HexViewer data={data} baseAddress={0x1000} />);

    expect(screen.getByText('00001000')).toBeInTheDocument();
  });

  it('displays byte count in footer', () => {
    const data = new Array(256).fill(0x00);
    render(<HexViewer data={data} />);

    expect(screen.getByText(/256 bytes/i)).toBeInTheDocument();
    expect(screen.getByText(/0\.25 KB/i)).toBeInTheDocument();
  });

  it('displays column headers', () => {
    const data = [0x41];
    render(<HexViewer data={data} />);

    expect(screen.getByText('Offset')).toBeInTheDocument();
    expect(screen.getByText('ASCII')).toBeInTheDocument();
    expect(screen.getByText('00')).toBeInTheDocument();
    expect(screen.getByText('01')).toBeInTheDocument();
  });

  it('handles custom bytesPerRow', () => {
    const data = new Array(32).fill(0x41);
    render(<HexViewer data={data} bytesPerRow={8} />);

    expect(screen.getByText('00000000')).toBeInTheDocument();
    expect(screen.getByText('00000008')).toBeInTheDocument();
    expect(screen.getByText('00000010')).toBeInTheDocument();
    expect(screen.getByText('00000018')).toBeInTheDocument();
  });
});
