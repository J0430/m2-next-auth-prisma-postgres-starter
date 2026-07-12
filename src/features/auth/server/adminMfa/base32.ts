// RFC 4648 base32 encode/decode for TOTP secrets (authenticator-app compatible).
// Uppercase, unpadded encoding; decoding is case-insensitive and ignores padding.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CHAR_TO_VALUE: ReadonlyMap<string, number> = new Map(
  ALPHABET.split("").map((char, index) => [char, index]),
);

// Encode raw bytes into an unpadded uppercase base32 string.
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += ALPHABET[(value >>> bits) & 0b11111];
    }
  }

  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 0b11111];
  }

  return output;
}

// Decode a base32 string (case-insensitive, padding tolerated) into raw bytes.
// Throws on any character outside the RFC 4648 alphabet so malformed secrets fail closed.
export function base32Decode(input: string): Uint8Array {
  const normalized = input.trim().toUpperCase().replace(/=+$/u, "");
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;

  for (const char of normalized) {
    const charValue = CHAR_TO_VALUE.get(char);
    if (charValue === undefined) {
      throw new Error("BASE32_INVALID_CHARACTER");
    }
    value = (value << 5) | charValue;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }

  return Uint8Array.from(bytes);
}
