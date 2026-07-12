/**
 * Filename pattern for round-trip response files written by the HOST into
 * the container's IPC input dir (`<type>_<requestId>.json`). They are
 * consumed by the MCP tool that is actively polling for them
 * (ipc-mcp-stdio.ts) — the input drain in index.ts must NEVER consume or
 * delete them, or that tool hangs until its 15s timeout and reports a
 * spurious failure.
 *
 * Keep in sync with the host's writeIpcResponse()/response writers in
 * src/ipc.ts: read_emails, announce, send_message (return_ts),
 * edit_message, delete_message.
 */
export const HOST_RESPONSE_FILE_PATTERN =
  /^(read_emails|announce|send_message|edit_message|delete_message)_/;
