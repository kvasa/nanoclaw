// Ambient type declaration for keystore.js — see backup/lib/env.d.ts for why
// this sibling .d.ts exists (backup/ is outside tsconfig rootDir/include, but
// a TS test under src/ imports this module and needs a type for it).
export function getKeystoreSecret(name: string): string | null;
