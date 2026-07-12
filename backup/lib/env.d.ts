// Ambient type declaration for env.js so src/env-parser-contract.test.ts
// (which lives under tsconfig's rootDir: "./src") can import this plain-JS
// module under `npm run typecheck`. backup/ itself is intentionally outside
// the TS build (rootDir/include) — this file is resolved by TypeScript's
// module resolution as a sibling declaration file, not compiled as part of
// the program, and has no effect on the runtime (Node/vitest import env.js
// directly and ignore .d.ts files).
export function parseEnv(content: string): Record<string, string>;
export function readEnvValues(
  envPath: string,
  keys?: string[],
): Record<string, string>;
