// Base64 and URL encoding/decoding. Runs only in the browser: never import api.js here.
//
// Encoding is not encryption: anyone can decode these, so they protect nothing.

function base64Encode(text) {
  // btoa() only accepts single-byte characters, so turn the text into UTF-8 bytes first.
  let binary = "";
  for (const byte of new TextEncoder().encode(text)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64Decode(text) {
  const binary = atob(text.trim());
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

// mode: "base64" or "url"; direction: "encode" or "decode". Throws an Error for invalid input.
export function convert(text, mode, direction) {
  try {
    if (mode === "base64") return direction === "encode" ? base64Encode(text) : base64Decode(text);
    return direction === "encode" ? encodeURIComponent(text) : decodeURIComponent(text);
  } catch {
    throw new Error(`This is not valid ${mode === "base64" ? "Base64" : "URL-encoded"} text.`);
  }
}
