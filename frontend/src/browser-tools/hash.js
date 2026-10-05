// Hash generator using the browser's built-in Web Crypto API.
// Runs only in the browser: never import api.js here.
// STUB: Role 3 implements this.

export const ALGORITHMS = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

// Returns the hex digest of `text` with `algorithm`.
export async function hashText(text, algorithm) {
  throw new Error(`Not implemented yet (${algorithm}, ${text.length} chars)`);
}
