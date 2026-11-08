const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodifica una cadena en Base32 a un Buffer de bytes (RFC 4648).
 * @param {string} base32Str
 * @returns {Buffer}
 */
function base32ToBuffer(base32Str) {
  const cleaned = base32Str.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const output = [];

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

  return Buffer.from(output);
}

/**
 * Calcula un código TOTP de 6 dígitos según RFC 6238 (HMAC-SHA1 + Dynamic Truncation).
 * @param {string} base32Secret - Clave secreta en Base32
 * @param {number} [timeStep] - Ventana de tiempo T = floor(UnixTimestamp / 30)
 * @returns {string} Código de 6 dígitos con ceros a la izquierda
 */
function generateTOTP(base32Secret, timeStep = Math.floor(Date.now() / 1000 / 30)) {
  const key = base32ToBuffer(base32Secret);

  // 1. Formatear T como entero de 64 bits Big-Endian (buffer de 8 bytes)
  const timeBuffer = Buffer.alloc(8);
  const high = Math.floor(timeStep / 0x100000000);
  const low = timeStep >>> 0;
  timeBuffer.writeUInt32BE(high, 0);
  timeBuffer.writeUInt32BE(low, 4);

  // 2. Hash Criptográfico: H = HMAC-SHA1(ClaveSecretaEnBytes, T)
  const hmac = crypto.createHmac('sha1', key).update(timeBuffer).digest();

  // 3. Dynamic Truncation (Truncamiento Dinámico)
  const offset = hmac[19] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  // 4. Obtener los 6 dígitos
  const otp = binCode % 1000000;
  return otp.toString().padStart(6, '0');
}

/**
 * Valida un código TOTP con tolerancia a desfase de reloj (Clock Skew) en C-1, C y C+1.
 * @param {string} base32Secret
 * @param {string} code
 * @param {number} [nowSeconds]
 * @returns {{ valid: boolean, matchedStep: number | null }}
 */
function verifyTOTPWithWindow(base32Secret, code, nowSeconds = Math.floor(Date.now() / 1000)) {
  const currentStep = Math.floor(nowSeconds / 30);
  const windows = [currentStep - 1, currentStep, currentStep + 1];

  for (const step of windows) {
    const candidate = generateTOTP(base32Secret, step);
    if (candidate === String(code).trim()) {
      return { valid: true, matchedStep: step };
    }
  }
  return { valid: false, matchedStep: null };
}

/**
 * Calcula SHA256(verifier) codificado en Base64URL sin relleno (RFC 7636).
 * @param {string} codeVerifier
 * @returns {string}
 */
function computeCodeChallenge(codeVerifier) {
  return crypto
    .createHash('sha256')
    .update(codeVerifier, 'ascii')
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

module.exports = {
  base32ToBuffer,
  generateTOTP,
  verifyTOTPWithWindow,
  computeCodeChallenge,
};

