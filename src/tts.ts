import { readEnvFile } from './env.js';
import { logger } from './logger.js';

export type TtsVoice =
  | 'alloy'
  | 'ash'
  | 'coral'
  | 'echo'
  | 'fable'
  | 'onyx'
  | 'nova'
  | 'sage'
  | 'shimmer';

const DEFAULT_VOICE: TtsVoice = 'ash';

/**
 * Synthesize speech from text using OpenAI TTS API.
 * Returns an MP3 buffer, or null if unavailable/failed.
 */
export async function synthesizeSpeech(
  text: string,
  voice: TtsVoice = DEFAULT_VOICE,
): Promise<Buffer | null> {
  const env = readEnvFile(['OPENAI_API_KEY']);
  const apiKey = env.OPENAI_API_KEY;

  if (!apiKey) {
    logger.debug('OPENAI_API_KEY not set, skipping TTS');
    return null;
  }

  if (!text || text.trim().length === 0) {
    logger.warn('Empty text, skipping TTS');
    return null;
  }

  try {
    const openaiModule = await import('openai');
    const OpenAI = openaiModule.default;

    const openai = new OpenAI({ apiKey });

    const response = await openai.audio.speech.create({
      model: 'tts-1',
      voice,
      input: text,
      response_format: 'mp3',
    });

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    logger.info(
      { textLength: text.length, audioSize: buffer.length, voice },
      'TTS synthesis completed',
    );
    return buffer;
  } catch (err) {
    logger.error({ err }, 'OpenAI TTS synthesis failed');
    return null;
  }
}
