// Hash generator using the browser's built-in Web Crypto API.
// Runs only in the browser: never import api.js here.
//
// MD5 is not offered: it is broken for security use, and Web Crypto doesn't support it.

export const ALGORITHMS = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

// Returns the hex digest of `text` (encoded as UTF-8) with `algorithm`.
export async function hashText(text, algorithm) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest(algorithm, bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
