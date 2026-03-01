import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('./env.js', () => ({
  readEnvFile: vi.fn().mockReturnValue({ OPENAI_API_KEY: 'sk-test-key' }),
}));

vi.mock('./logger.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

const mockCreate = vi.hoisted(() => vi.fn().mockResolvedValue('Hello world'));

vi.mock('openai', () => ({
  default: class MockOpenAI {
    constructor() {}
    audio = {
      transcriptions: {
        create: mockCreate,
      },
    };
  },
  toFile: vi.fn().mockResolvedValue('mock-file'),
}));

import { transcribeBuffer } from './transcription.js';
import { readEnvFile } from './env.js';

describe('transcribeBuffer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns transcript on success', async () => {
    const buffer = Buffer.from('fake audio data');
    const result = await transcribeBuffer(buffer, 'voice.ogg', 'audio/ogg');
    expect(result).toBe('Hello world');
  });

  it('returns null when OPENAI_API_KEY is not set', async () => {
    vi.mocked(readEnvFile).mockReturnValueOnce({});
    const result = await transcribeBuffer(Buffer.from('data'));
    expect(result).toBeNull();
  });

  it('returns null for empty buffer', async () => {
    const result = await transcribeBuffer(Buffer.alloc(0));
    expect(result).toBeNull();
  });

  it('returns null on API error', async () => {
    mockCreate.mockRejectedValueOnce(new Error('API error'));
    const result = await transcribeBuffer(Buffer.from('data'));
    expect(result).toBeNull();
  });

  it('trims whitespace from transcript', async () => {
    mockCreate.mockResolvedValueOnce('  Hello world  ');
    const result = await transcribeBuffer(Buffer.from('data'));
    expect(result).toBe('Hello world');
  });

  it('returns null for empty transcript', async () => {
    mockCreate.mockResolvedValueOnce('   ');
    const result = await transcribeBuffer(Buffer.from('data'));
    expect(result).toBeNull();
  });
});
