import * as Crypto from 'expo-crypto';

const URL_SAFE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

/**
 * Genera una cadena aleatoria de alta entropía usando bytes criptográficos de expo-crypto.
 */
function generateRandomUrlSafeString(length: number): string {
  const randomBytes = Crypto.getRandomBytes(length);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += URL_SAFE_CHARSET[randomBytes[i] % URL_SAFE_CHARSET.length];
  }
  return result;
}

/**
 * Convierte una cadena Base64 estándar a Base64URL sin relleno (unpadded) según RFC 7636.
 */
function toBase64UrlUnpadded(base64: string): string {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Genera el code_verifier (entre 43 y 128 caracteres URL-safe).
 */
export function generateCodeVerifier(length = 64): string {
  if (length < 43 || length > 128) {
    throw new Error('RFC 7636: code_verifier debe tener entre 43 y 128 caracteres.');
  }
  return generateRandomUrlSafeString(length);
}

/**
 * Calcula code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) sin padding.
 */
export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const digestBase64 = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    codeVerifier,
    { encoding: Crypto.CryptoEncoding.BASE64 }
  );
  return toBase64UrlUnpadded(digestBase64);
}

/**
 * Genera un parámetro state único anti-CSRF para la petición de autorización.
 */
export function generateAntiCsrfState(length = 32): string {
  return generateRandomUrlSafeString(length);
}

