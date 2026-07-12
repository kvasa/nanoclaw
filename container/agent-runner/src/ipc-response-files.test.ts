import { describe, expect, it } from 'vitest';

import { HOST_RESPONSE_FILE_PATTERN } from './ipc-response-files.js';

describe('HOST_RESPONSE_FILE_PATTERN', () => {
  it('matches every host response filename shape', () => {
    expect(HOST_RESPONSE_FILE_PATTERN.test('read_emails_abc123.json')).toBe(
      true,
    );
    expect(HOST_RESPONSE_FILE_PATTERN.test('announce_abc123.json')).toBe(
      true,
    );
    expect(HOST_RESPONSE_FILE_PATTERN.test('send_message_abc123.json')).toBe(
      true,
    );
    expect(HOST_RESPONSE_FILE_PATTERN.test('edit_message_abc123.json')).toBe(
      true,
    );
    expect(
      HOST_RESPONSE_FILE_PATTERN.test('delete_message_abc123.json'),
    ).toBe(true);
  });

  it('does not match normal container input messages', () => {
    expect(
      HOST_RESPONSE_FILE_PATTERN.test('1720000000000-message.json'),
    ).toBe(false);
    expect(HOST_RESPONSE_FILE_PATTERN.test('message_1.json')).toBe(false);
    expect(HOST_RESPONSE_FILE_PATTERN.test('_close')).toBe(false);
  });

  it('matches the requestId charset used by the host ([a-zA-Z0-9_-])', () => {
    expect(HOST_RESPONSE_FILE_PATTERN.test('edit_message_a-B_9.json')).toBe(
      true,
    );
  });
});
