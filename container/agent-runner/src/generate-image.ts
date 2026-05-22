/**
 * Image generation via Google Gemini "Nano Banana 2".
 *
 * Extracted from ipc-mcp-stdio.ts so the validation + API call logic is unit-
 * testable without booting the full MCP server. The MCP tool wrapper around
 * generateImage() is the only thing that lives in ipc-mcp-stdio.ts.
 */
import fs from 'fs';
import path from 'path';

export const DEFAULT_GEMINI_IMAGE_MODEL = 'gemini-3.1-flash-image-preview';
export const DEFAULT_GEMINI_API_BASE =
  'https://generativelanguage.googleapis.com/v1beta';
// Gemini accepts up to ~20 MB of inline image data per request; keep a safety
// margin so base64 expansion and a long prompt still fit.
export const GEMINI_MAX_INPUT_BYTES = 15 * 1024 * 1024;
export const DEFAULT_GEMINI_TIMEOUT_MS = 120_000;

export const DEFAULT_WORKSPACE_GROUP = '/workspace/group';
export const ALLOWED_SOURCE_ROOTS = [
  '/workspace/group/',
  '/workspace/global/',
  '/workspace/extra/',
  '/workspace/backups/',
];

export function mimeFromExt(ext: string): string {
  switch (ext.toLowerCase()) {
    case '.jpg':
    case '.jpeg':
      return 'image/jpeg';
    case '.png':
      return 'image/png';
    case '.webp':
      return 'image/webp';
    case '.gif':
      return 'image/gif';
    default:
      return 'application/octet-stream';
  }
}

export function extFromMime(mime: string): string {
  if (mime === 'image/jpeg') return '.jpg';
  if (mime === 'image/png') return '.png';
  if (mime === 'image/webp') return '.webp';
  if (mime === 'image/gif') return '.gif';
  return '.bin';
}

export function isSafeFilename(name: string): boolean {
  // Only allow letters/digits/dot/underscore/dash; reject any path separators
  // or traversal sequences. Auto-appended timestamp keeps things unique.
  return /^[a-zA-Z0-9._-]+$/.test(name) && !name.includes('..');
}

export function isAllowedSourcePath(
  p: string,
  roots: readonly string[] = ALLOWED_SOURCE_ROOTS,
): boolean {
  const resolved = path.resolve(p);
  return roots.some(
    (root) => resolved === root.slice(0, -1) || resolved.startsWith(root),
  );
}

export interface GeminiInlineData {
  mime_type?: string;
  mimeType?: string;
  data: string;
}

export interface GeminiPart {
  text?: string;
  inline_data?: GeminiInlineData;
  inlineData?: GeminiInlineData;
}

export interface GenerateImageArgs {
  prompt: string;
  source_image_path?: string;
  output_filename?: string;
}

export interface GenerateImageOptions {
  apiKey?: string;
  apiBase?: string;
  model?: string;
  workspaceGroup?: string;
  allowedSourceRoots?: readonly string[];
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  now?: () => Date;
}

export type GenerateImageResult =
  | {
      status: 'ok';
      outputPath: string;
      bytes: number;
      mime: string;
      caption: string;
    }
  | { status: 'error'; message: string };

/**
 * Generate or edit an image. Returns either the path of the saved image
 * or a structured error. Pure(ish) — host filesystem write is the only
 * side effect, and the workspace root is configurable for tests.
 */
export async function generateImage(
  args: GenerateImageArgs,
  options: GenerateImageOptions = {},
): Promise<GenerateImageResult> {
  const apiKey = options.apiKey ?? process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return {
      status: 'error',
      message:
        'Image generation is not configured: GEMINI_API_KEY is missing on the host. Ask the user to add it to .env.',
    };
  }

  const apiBase =
    options.apiBase ?? process.env.GEMINI_API_BASE ?? DEFAULT_GEMINI_API_BASE;
  const model =
    options.model ??
    process.env.GEMINI_IMAGE_MODEL ??
    DEFAULT_GEMINI_IMAGE_MODEL;
  const workspaceGroup = options.workspaceGroup ?? DEFAULT_WORKSPACE_GROUP;
  const allowedRoots = options.allowedSourceRoots ?? ALLOWED_SOURCE_ROOTS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_GEMINI_TIMEOUT_MS;
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? (() => new Date());

  const parts: GeminiPart[] = [{ text: args.prompt }];

  if (args.source_image_path) {
    if (!isAllowedSourcePath(args.source_image_path, allowedRoots)) {
      return {
        status: 'error',
        message: `source_image_path must live under one of: ${allowedRoots.join(', ')}`,
      };
    }
    let buf: Buffer;
    try {
      buf = fs.readFileSync(args.source_image_path);
    } catch (err) {
      return {
        status: 'error',
        message: `Cannot read source image: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    if (buf.length > GEMINI_MAX_INPUT_BYTES) {
      return {
        status: 'error',
        message: `Source image too large (${buf.length} bytes, limit ${GEMINI_MAX_INPUT_BYTES}). Resize it first.`,
      };
    }
    const mime = mimeFromExt(path.extname(args.source_image_path));
    if (mime === 'application/octet-stream') {
      return {
        status: 'error',
        message: 'Unsupported source image format. Use .jpg / .png / .webp / .gif.',
      };
    }
    parts.push({
      inline_data: { mime_type: mime, data: buf.toString('base64') },
    });
  }

  // Validate output filename early so we don't waste an API call on a bad
  // filename request.
  const base = args.output_filename ?? 'generated-image';
  if (!isSafeFilename(base)) {
    return {
      status: 'error',
      message:
        'output_filename must contain only letters, digits, dot, underscore, or dash.',
    };
  }

  const body = JSON.stringify({ contents: [{ parts }] });
  const url = `${apiBase}/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;

  let response: Response;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    response = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    return {
      status: 'error',
      message: `Gemini API request failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  clearTimeout(timer);

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    return {
      status: 'error',
      message: `Gemini API returned ${response.status}: ${text.slice(0, 500)}`,
    };
  }

  let payload: {
    candidates?: Array<{ content?: { parts?: GeminiPart[] } }>;
  };
  try {
    payload = await response.json();
  } catch (err) {
    return {
      status: 'error',
      message: `Failed to parse Gemini response: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  let imageBytes: Buffer | undefined;
  let imageMime = 'image/jpeg';
  let captionText = '';
  for (const cand of payload.candidates ?? []) {
    for (const part of cand.content?.parts ?? []) {
      const inline = part.inline_data ?? part.inlineData;
      if (inline?.data && !imageBytes) {
        imageBytes = Buffer.from(inline.data, 'base64');
        imageMime = inline.mime_type ?? inline.mimeType ?? imageMime;
      } else if (part.text) {
        captionText += (captionText ? '\n' : '') + part.text;
      }
    }
  }

  if (!imageBytes) {
    return {
      status: 'error',
      message: `Gemini returned no image. Model response: ${captionText.slice(0, 500) || '(empty)'}`,
    };
  }

  const ext = extFromMime(imageMime);
  // Strip any pre-existing extension so we append the one matching the
  // model's actual output (it usually returns JPEG even for PNG inputs).
  const baseWithoutExt = base.replace(/\.[a-zA-Z0-9]{1,6}$/, '');
  const timestamp = now()
    .toISOString()
    .replace(/[:.]/g, '-')
    .replace('T', '_')
    .slice(0, 19);
  const filename = `${baseWithoutExt}-${timestamp}${ext}`;
  const outputPath = path.join(workspaceGroup, filename);

  // Defense in depth: confirm we're still inside the workspace.
  const wsRoot = workspaceGroup.endsWith('/') ? workspaceGroup : workspaceGroup + '/';
  if (!outputPath.startsWith(wsRoot)) {
    return { status: 'error', message: 'Path traversal blocked.' };
  }

  try {
    fs.mkdirSync(workspaceGroup, { recursive: true });
    fs.writeFileSync(outputPath, imageBytes);
  } catch (err) {
    return {
      status: 'error',
      message: `Failed to write image: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  return {
    status: 'ok',
    outputPath,
    bytes: imageBytes.length,
    mime: imageMime,
    caption: captionText.trim(),
  };
}
