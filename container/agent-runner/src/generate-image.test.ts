import fs from 'fs';
import os from 'os';
import path from 'path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ALLOWED_SOURCE_ROOTS,
  extFromMime,
  generateImage,
  isAllowedSourcePath,
  isSafeFilename,
  mimeFromExt,
} from './generate-image.js';

describe('helpers', () => {
  it('mimeFromExt maps common extensions', () => {
    expect(mimeFromExt('.jpg')).toBe('image/jpeg');
    expect(mimeFromExt('.JPEG')).toBe('image/jpeg');
    expect(mimeFromExt('.png')).toBe('image/png');
    expect(mimeFromExt('.webp')).toBe('image/webp');
    expect(mimeFromExt('.gif')).toBe('image/gif');
    expect(mimeFromExt('.tiff')).toBe('application/octet-stream');
  });

  it('extFromMime is the inverse for supported types', () => {
    expect(extFromMime('image/jpeg')).toBe('.jpg');
    expect(extFromMime('image/png')).toBe('.png');
    expect(extFromMime('image/webp')).toBe('.webp');
    expect(extFromMime('image/gif')).toBe('.gif');
    expect(extFromMime('text/plain')).toBe('.bin');
  });

  it('isSafeFilename rejects path traversal and separators', () => {
    expect(isSafeFilename('foo.png')).toBe(true);
    expect(isSafeFilename('garden_2026-05_v1')).toBe(true);
    expect(isSafeFilename('../etc/passwd')).toBe(false);
    expect(isSafeFilename('a/b')).toBe(false);
    expect(isSafeFilename('a\\b')).toBe(false);
    expect(isSafeFilename('a..b')).toBe(false);
    expect(isSafeFilename('')).toBe(false);
    expect(isSafeFilename('a b')).toBe(false);
  });

  it('isAllowedSourcePath accepts the workspace roots and rejects everything else', () => {
    expect(isAllowedSourcePath('/workspace/group/photo.jpg')).toBe(true);
    expect(
      isAllowedSourcePath('/workspace/group/slack-uploads/IMG_4951.jpg'),
    ).toBe(true);
    expect(isAllowedSourcePath('/workspace/global/CLAUDE.md')).toBe(true);
    expect(isAllowedSourcePath('/workspace/extra/repo/img.png')).toBe(true);
    expect(isAllowedSourcePath('/etc/passwd')).toBe(false);
    expect(isAllowedSourcePath('/tmp/x.jpg')).toBe(false);
    // Path traversal that would resolve outside the allowed roots:
    expect(
      isAllowedSourcePath('/workspace/group/../../etc/passwd'),
    ).toBe(false);
  });

  it('ALLOWED_SOURCE_ROOTS does not include /workspace/ipc/', () => {
    // ipc must NEVER be a source — agent could otherwise smuggle credentials
    // it sees in IPC snapshots into the model.
    expect(ALLOWED_SOURCE_ROOTS).not.toContain('/workspace/ipc/');
  });
});

describe('generateImage', () => {
  let tmpRoot: string;

  function writePngFixture(p: string): void {
    // Minimal 1×1 PNG (8 bytes signature + IHDR + IDAT + IEND)
    const png = Buffer.from(
      '89504e470d0a1a0a0000000d49484452000000010000000108020000009077533de0000000164944415478daedc1010100000080900fef1f0820000000ffff03000006000557bf67ac0000000049454e44ae426082',
      'hex',
    );
    fs.writeFileSync(p, png);
  }

  function mockOkResponse(b64: string, mime = 'image/jpeg', text = ''): Response {
    return {
      ok: true,
      status: 200,
      async json() {
        return {
          candidates: [
            {
              content: {
                parts: [
                  ...(text ? [{ text }] : []),
                  { inline_data: { mime_type: mime, data: b64 } },
                ],
              },
            },
          ],
        };
      },
      async text() {
        return '';
      },
    } as unknown as Response;
  }

  beforeEach(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nanoclaw-genimg-'));
  });

  afterEach(() => {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  it('text-to-image: writes the returned image into the workspace dir', async () => {
    const wsGroup = path.join(tmpRoot, 'group');
    fs.mkdirSync(wsGroup);
    const fetchImpl = vi.fn(
      async () =>
        mockOkResponse(
          Buffer.from('fake-image-bytes').toString('base64'),
          'image/jpeg',
          'Done.',
        ),
    );

    const result = await generateImage(
      { prompt: 'A robot watering a lavender garden, photorealistic.' },
      {
        apiKey: 'AIza-test',
        workspaceGroup: wsGroup,
        fetchImpl: fetchImpl as unknown as typeof fetch,
        now: () => new Date('2026-05-22T18:00:00.000Z'),
      },
    );

    expect(result.status).toBe('ok');
    if (result.status !== 'ok') throw new Error('unreachable');
    expect(result.outputPath).toBe(
      path.join(wsGroup, 'generated-image-2026-05-22_18-00-00.jpg'),
    );
    expect(result.bytes).toBe(Buffer.from('fake-image-bytes').length);
    expect(result.mime).toBe('image/jpeg');
    expect(fs.readFileSync(result.outputPath)).toEqual(
      Buffer.from('fake-image-bytes'),
    );

    // Verify the request body included the prompt and no inline_data part
    // (text-to-image — no source image).
    const callArgs = fetchImpl.mock.calls[0];
    expect(callArgs[0]).toContain(
      'gemini-3.1-flash-image-preview:generateContent',
    );
    expect(callArgs[0]).toContain('key=AIza-test');
    const body = JSON.parse((callArgs[1] as RequestInit).body as string);
    expect(body.contents[0].parts[0].text).toContain('robot watering');
    expect(body.contents[0].parts.length).toBe(1);
  });

  it('image-to-image: includes source image as inline_data, returns edited output', async () => {
    const wsGroup = path.join(tmpRoot, 'group');
    const uploadsDir = path.join(wsGroup, 'slack-uploads');
    fs.mkdirSync(uploadsDir, { recursive: true });
    const sourcePath = path.join(uploadsDir, 'IMG_4951.png');
    writePngFixture(sourcePath);
    const allowed = [`${wsGroup}/`];

    const fetchImpl = vi.fn(async () =>
      mockOkResponse(
        Buffer.from('edited-bytes').toString('base64'),
        'image/jpeg',
      ),
    );

    const result = await generateImage(
      {
        prompt: 'Nahraď hosty levandulí, zachovej dlažbu a bambus vlevo.',
        source_image_path: sourcePath,
        output_filename: 'garden_v1',
      },
      {
        apiKey: 'AIza-test',
        workspaceGroup: wsGroup,
        allowedSourceRoots: allowed,
        fetchImpl: fetchImpl as unknown as typeof fetch,
        now: () => new Date('2026-05-22T18:00:00.000Z'),
      },
    );

    expect(result.status).toBe('ok');
    if (result.status !== 'ok') throw new Error('unreachable');
    // Custom filename used; extension forced to match the model's actual mime.
    expect(path.basename(result.outputPath)).toBe(
      'garden_v1-2026-05-22_18-00-00.jpg',
    );

    const body = JSON.parse(
      (fetchImpl.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.contents[0].parts).toHaveLength(2);
    expect(body.contents[0].parts[1].inline_data.mime_type).toBe('image/png');
    expect(typeof body.contents[0].parts[1].inline_data.data).toBe('string');
    expect(body.contents[0].parts[1].inline_data.data.length).toBeGreaterThan(
      0,
    );
  });

  it('refuses source images outside the allowlist (defends against /etc/passwd etc.)', async () => {
    const wsGroup = path.join(tmpRoot, 'group');
    fs.mkdirSync(wsGroup);
    const evil = path.join(tmpRoot, 'evil.png');
    writePngFixture(evil);

    const fetchImpl = vi.fn();
    const result = await generateImage(
      { prompt: 'edit', source_image_path: evil },
      {
        apiKey: 'AIza',
        workspaceGroup: wsGroup,
        allowedSourceRoots: [`${wsGroup}/`],
        fetchImpl: fetchImpl as unknown as typeof fetch,
      },
    );

    expect(result.status).toBe('error');
    if (result.status === 'error') {
      expect(result.message).toMatch(/source_image_path must live under/);
    }
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('rejects unsafe output_filename before calling the API', async () => {
    const wsGroup = path.join(tmpRoot, 'group');
    fs.mkdirSync(wsGroup);
    const fetchImpl = vi.fn();

    const result = await generateImage(
      { prompt: 'cat', output_filename: '../../../etc/x' },
      {
        apiKey: 'AIza',
        workspaceGroup: wsGroup,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      },
    );

    expect(result.status).toBe('error');
    if (result.status === 'error') {
      expect(result.message).toMatch(/output_filename must contain only/);
    }
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('errors out helpfully when GEMINI_API_KEY is missing', async () => {
    const wsGroup = path.join(tmpRoot, 'group');
    fs.mkdirSync(wsGroup);
    const previous = process.env.GEMINI_API_KEY;
    delete process.env.GEMINI_API_KEY;
    try {
      const result = await generateImage(
        { prompt: 'cat' },
        { workspaceGroup: wsGroup, fetchImpl: vi.fn() as unknown as typeof fetch },
      );
      expect(result.status).toBe('error');
      if (result.status === 'error') {
        expect(result.message).toMatch(/GEMINI_API_KEY is missing/);
      }
    } finally {
      if (previous !== undefined) process.env.GEMINI_API_KEY = previous;
    }
  });

  it('surfaces upstream HTTP errors with the body snippet', async () => {
    const wsGroup = path.join(tmpRoot, 'group');
    fs.mkdirSync(wsGroup);
    const fetchImpl = vi.fn(
      async () =>
        ({
          ok: false,
          status: 429,
          async json() {
            throw new Error('not used');
          },
          async text() {
            return 'Quota exceeded for project foo';
          },
        }) as unknown as Response,
    );

    const result = await generateImage(
      { prompt: 'cat' },
      {
        apiKey: 'AIza',
        workspaceGroup: wsGroup,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      },
    );

    expect(result.status).toBe('error');
    if (result.status === 'error') {
      expect(result.message).toMatch(/Gemini API returned 429/);
      expect(result.message).toMatch(/Quota exceeded/);
    }
  });

  it('returns an error when the model responds with text only (no image)', async () => {
    const wsGroup = path.join(tmpRoot, 'group');
    fs.mkdirSync(wsGroup);
    const fetchImpl = vi.fn(
      async () =>
        ({
          ok: true,
          status: 200,
          async json() {
            return {
              candidates: [
                {
                  content: {
                    parts: [{ text: 'I refuse to draw violent content.' }],
                  },
                },
              ],
            };
          },
          async text() {
            return '';
          },
        }) as unknown as Response,
    );

    const result = await generateImage(
      { prompt: 'unsafe prompt' },
      {
        apiKey: 'AIza',
        workspaceGroup: wsGroup,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      },
    );

    expect(result.status).toBe('error');
    if (result.status === 'error') {
      expect(result.message).toMatch(/no image/);
      expect(result.message).toMatch(/I refuse to draw/);
    }
  });
});
