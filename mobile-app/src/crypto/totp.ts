const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Valida y limpia una semilla en formato Base32.
 */
export function cleanBase32Secret(input: string): string {
  return input.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
}

export function isValidBase32Secret(input: string): boolean {
  const cleaned = cleanBase32Secret(input);
  if (cleaned.length < 8) return false;
  for (let i = 0; i < cleaned.length; i++) {
    if (!BASE32_ALPHABET.includes(cleaned[i])) {
      return false;
    }
  }
  return true;
}

/**
 * Decodifica una cadena Base32 a un arreglo de bytes Uint8Array (RFC 4648).
 */
export function base32ToBytes(base32Str: string): Uint8Array {
  const cleaned = cleanBase32Secret(base32Str);
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) {
      throw new Error(`Carácter Base32 inválido: ${cleaned[i]}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

/**
 * Implementación pura de SHA-1 (FIPS 180-4) sobre Uint8Array (20 bytes de salida).
 * Garantiza ejecución síncrona, determinista y 100% en Modo Avión sin llamadas de red.
 */
function sha1Bytes(message: Uint8Array): Uint8Array {
  const ml = message.length * 8;
  const withOne = message.length + 1;
  const padLen = (64 - ((withOne + 8) % 64)) % 64;
  const totalLen = withOne + padLen + 8;

  const padded = new Uint8Array(totalLen);
  padded.set(message);
  padded[message.length] = 0x80;

  const view = new DataView(padded.buffer);
  const highBits = Math.floor(ml / 0x100000000);
  const lowBits = ml >>> 0;
  view.setUint32(totalLen - 8, highBits, false);
  view.setUint32(totalLen - 4, lowBits, false);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  const w = new Uint32Array(80);

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 80; i++) {
      const n = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = ((n << 1) | (n >>> 31)) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    for (let i = 0; i < 80; i++) {
      let f = 0;
      let k = 0;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }

      const temp = ((((a << 5) | (a >>> 27)) >>> 0) + (f >>> 0) + e + k + w[i]) >>> 0;
      e = d;
      d = c;
      c = ((b << 30) | (b >>> 2)) >>> 0;
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);
  return out;
}

/**
 * Implementación de HMAC-SHA1 según RFC 2104:
 * HMAC(K, m) = SHA1((K' ^ opad) || SHA1((K' ^ ipad) || m))
 */
export function hmacSha1(keyBytes: Uint8Array, messageBytes: Uint8Array): Uint8Array {
  const blockSize = 64;
  let normalizedKey = keyBytes;

  if (normalizedKey.length > blockSize) {
    normalizedKey = sha1Bytes(normalizedKey);
  }

  const keyBlock = new Uint8Array(blockSize);
  keyBlock.set(normalizedKey);

  const oKeyPad = new Uint8Array(blockSize);
  const iKeyPad = new Uint8Array(blockSize);

  for (let i = 0; i < blockSize; i++) {
    oKeyPad[i] = keyBlock[i] ^ 0x5c;
    iKeyPad[i] = keyBlock[i] ^ 0x36;
  }

  const innerInput = new Uint8Array(blockSize + messageBytes.length);
  innerInput.set(iKeyPad, 0);
  innerInput.set(messageBytes, blockSize);
  const innerHash = sha1Bytes(innerInput);

  const outerInput = new Uint8Array(blockSize + innerHash.length);
  outerInput.set(oKeyPad, 0);
  outerInput.set(innerHash, blockSize);
  return sha1Bytes(outerInput);
}

/**
 * Algoritmo TOTP desde cero según RFC 6238:
 * 1. Ventana de Tiempo: T = floor(UnixTimestamp / 30) en buffer Big-Endian de 8 bytes.
 * 2. Hash Criptográfico: H = HMAC-SHA1(ClaveSecretaEnBytes, T)
 * 3. Dynamic Truncation: offset = H[19] & 0x0F -> bin_code de 31 bits
 * 4. 6 dígitos: bin_code % 1000000 con padding de ceros a la izquierda.
 */
export function generateTOTP(
  base32Secret: string,
  unixTimestampSeconds = Math.floor(Date.now() / 1000)
): { code: string; remainingSeconds: number; timeStep: number } {
  const keyBytes = base32ToBytes(base32Secret);
  const timeStep = Math.floor(unixTimestampSeconds / 30);
  const remainingSeconds = 30 - (unixTimestampSeconds % 30);

  // 1. Formatear T como entero de 64 bits en formato Big-Endian (buffer de 8 bytes)
  const timeBuffer = new Uint8Array(8);
  const view = new DataView(timeBuffer.buffer);
  const high = Math.floor(timeStep / 0x100000000);
  const low = timeStep >>> 0;
  view.setUint32(0, high, false);
  view.setUint32(4, low, false);

  // 2. Hash Criptográfico H = HMAC-SHA1(ClaveSecretaEnBytes, T)
  const hmac = hmacSha1(keyBytes, timeBuffer);

  // 3. Dynamic Truncation (Truncamiento Dinámico)
  const offset = hmac[19] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  // 4. Obtener los 6 dígitos con ceros a la izquierda
  const totp = (binCode % 1000000).toString().padStart(6, '0');

  return {
    code: totp,
    remainingSeconds,
    timeStep,
  };
}

/**
 * Extrae el secreto Base32, cuenta y emisor desde un URI otpauth://totp/...
 * Ejemplo: otpauth://totp/UniSabana:estudiante@unisabana.edu.co?secret=JBSWY3DPEHPK3PXP&issuer=UniSabana
 */
export function parseOtpAuthUri(input: string): {
  secret: string;
  label?: string;
  issuer?: string;
} | null {
  const trimmed = input.trim();

  if (trimmed.toLowerCase().startsWith('otpauth://totp/')) {
    try {
      const url = new URL(trimmed);
      const secretParam = url.searchParams.get('secret');
      const issuerParam = url.searchParams.get('issuer') || undefined;
      const rawLabel = decodeURIComponent(url.pathname.replace(/^\/+/, ''));

      if (secretParam && isValidBase32Secret(secretParam)) {
        return {
          secret: cleanBase32Secret(secretParam),
          label: rawLabel || undefined,
          issuer: issuerParam,
        };
      }
      return null;
    } catch {
      return null;
    }
  }

  if (isValidBase32Secret(trimmed)) {
    return {
      secret: cleanBase32Secret(trimmed),
    };
  }

  return null;
}

