import React, { useMemo } from 'react';
import { Box, Typography } from '@mui/material';

interface HexViewerProps {
  data: Uint8Array | number[] | null;
  baseAddress?: number;
  bytesPerRow?: number;
  height?: string;
}

function toPrintableChar(byte: number): string {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.';
}

function toHex(n: number, pad: number): string {
  return n.toString(16).padStart(pad, '0');
}

export default function HexViewer({
  data,
  baseAddress = 0,
  bytesPerRow = 16,
  height = '100%',
}: HexViewerProps) {
  const rows = useMemo(() => {
    if (!data || data.length === 0) return [];

    const bytes = data instanceof Uint8Array ? Array.from(data) : data;
    const result: { address: number; hex: string[]; ascii: string }[] = [];

    for (let i = 0; i < bytes.length; i += bytesPerRow) {
      const rowBytes = bytes.slice(i, i + bytesPerRow);
      const hex = rowBytes.map((b) => toHex(b, 2));
      const ascii = rowBytes.map(toPrintableChar).join('');

      while (hex.length < bytesPerRow) {
        hex.push('  ');
      }

      result.push({
        address: baseAddress + i,
        hex,
        ascii: ascii.padEnd(bytesPerRow, ' '),
      });
    }

    return result;
  }, [data, baseAddress, bytesPerRow]);

  if (!data || data.length === 0) {
    return (
      <Box
        sx={{
          height,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'text.disabled',
        }}
      >
        <Typography variant="body2">No binary data</Typography>
      </Box>
    );
  }

  return (
    <Box
      sx={{
        height,
        overflow: 'auto',
        bgcolor: '#1a1a1a',
        fontFamily: '"JetBrains Mono", "Fira Code", "Consolas", monospace',
        fontSize: '0.75rem',
        lineHeight: 1.5,
        p: 1,
      }}
    >
      <Box
        sx={{
          display: 'flex',
          color: 'text.disabled',
          borderBottom: '1px solid',
          borderColor: 'divider',
          pb: 0.5,
          mb: 0.5,
          position: 'sticky',
          top: 0,
          bgcolor: '#1a1a1a',
          zIndex: 1,
        }}
      >
        <Box sx={{ width: 80, flexShrink: 0 }}>Offset</Box>
        <Box sx={{ flex: 1 }}>
          {Array.from({ length: bytesPerRow }, (_, i) => (
            <span key={i} style={{ width: '1.8em', display: 'inline-block', textAlign: 'center' }}>
              {toHex(i, 2).toUpperCase()}
            </span>
          ))}
        </Box>
        <Box sx={{ width: bytesPerRow * 8 + 16, textAlign: 'center' }}>ASCII</Box>
      </Box>

      {rows.map((row, idx) => (
        <Box
          key={idx}
          sx={{
            display: 'flex',
            '&:hover': { bgcolor: 'rgba(255,255,255,0.03)' },
          }}
        >
          <Box sx={{ width: 80, flexShrink: 0, color: '#6a9955' }}>
            {toHex(row.address, 8)}
          </Box>

          <Box sx={{ flex: 1 }}>
            {row.hex.map((byte, i) => {
              const value = parseInt(byte, 16);
              const isNull = byte === '00';
              const isHigh = !isNaN(value) && value >= 0x80;
              const isPrintable = !isNaN(value) && value >= 0x20 && value <= 0x7e;

              return (
                <span
                  key={i}
                  style={{
                    width: '1.8em',
                    display: 'inline-block',
                    textAlign: 'center',
                    color: isNull
                      ? '#555'
                      : isHigh
                      ? '#ce9178'
                      : isPrintable
                      ? '#9cdcfe'
                      : '#d4d4d4',
                  }}
                >
                  {byte.toUpperCase()}
                </span>
              );
            })}
          </Box>

          <Box
            sx={{
              width: bytesPerRow * 8 + 16,
              color: '#b5cea8',
              pl: 2,
              borderLeft: '1px solid',
              borderColor: 'divider',
            }}
          >
            {row.ascii.split('').map((char, i) => (
              <span
                key={i}
                style={{
                  color: char === '.' ? '#555' : '#b5cea8',
                }}
              >
                {char}
              </span>
            ))}
          </Box>
        </Box>
      ))}

      <Box
        sx={{
          mt: 1,
          pt: 1,
          borderTop: '1px solid',
          borderColor: 'divider',
          color: 'text.disabled',
          fontSize: '0.65rem',
        }}
      >
        {data.length} bytes ({(data.length / 1024).toFixed(2)} KB) • Base: 0x
        {toHex(baseAddress, 8)}
      </Box>
    </Box>
  );
}

