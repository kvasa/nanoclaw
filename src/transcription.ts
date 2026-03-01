import { readEnvFile } from './env.js';
import { logger } from './logger.js';

/**
 * Transcribe an audio buffer using OpenAI Whisper API.
 * Returns the transcript text, or null if unavailable/failed.
 */
export async function transcribeBuffer(
  audioBuffer: Buffer,
  filename = 'audio.ogg',
  mimeType = 'audio/ogg',
): Promise<string | null> {
  const env = readEnvFile(['OPENAI_API_KEY']);
  const apiKey = env.OPENAI_API_KEY;

  if (!apiKey) {
    logger.debug('OPENAI_API_KEY not set, skipping transcription');
    return null;
  }

  if (!audioBuffer || audioBuffer.length === 0) {
    logger.warn('Empty audio buffer, skipping transcription');
    return null;
  }

  try {
    const openaiModule = await import('openai');
    const OpenAI = openaiModule.default;
    const toFile = openaiModule.toFile;

    const openai = new OpenAI({ apiKey });

    const file = await toFile(audioBuffer, filename, { type: mimeType });

    const transcription = await openai.audio.transcriptions.create({
      file,
      model: 'gpt-4o-transcribe',
      response_format: 'text',
      language: 'cs',
    });

    const text = (transcription as unknown as string).trim();

    if (!text) {
      logger.debug('Transcription returned empty text');
      return null;
    }

    logger.info({ length: text.length }, 'Audio transcription completed');
    return text;
  } catch (err) {
    logger.error({ err }, 'OpenAI transcription failed');
    return null;
  }
}
