import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

const REFRESH_TOKEN_KEY = 'unisabana_secure_refresh_token';
const TOTP_SECRET_KEY = 'unisabana_secure_totp_secret';

/**
 * Persiste el refresh_token en el enclave seguro por hardware (iOS Keychain / Android Keystore).
 * En web (solo para previsualización local si se corre en navegador) usa fallback en memoria/session.
 */
let webFallbackStore: Record<string, string> = {};

export async function saveRefreshToken(token: string): Promise<void> {
  if (Platform.OS === 'web') {
    webFallbackStore[REFRESH_TOKEN_KEY] = token;
    return;
  }
  await SecureStore.setItemAsync(REFRESH_TOKEN_KEY, token, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

export async function getRefreshToken(): Promise<string | null> {
  if (Platform.OS === 'web') {
    return webFallbackStore[REFRESH_TOKEN_KEY] ?? null;
  }
  return SecureStore.getItemAsync(REFRESH_TOKEN_KEY);
}

export async function clearRefreshToken(): Promise<void> {
  if (Platform.OS === 'web') {
    delete webFallbackStore[REFRESH_TOKEN_KEY];
    return;
  }
  await SecureStore.deleteItemAsync(REFRESH_TOKEN_KEY);
}

/**
 * Persiste la semilla TOTP en el enclave seguro del dispositivo para operar 100% en Modo Avión.
 */
export async function saveTotpSecret(secret: string): Promise<void> {
  if (Platform.OS === 'web') {
    webFallbackStore[TOTP_SECRET_KEY] = secret;
    return;
  }
  await SecureStore.setItemAsync(TOTP_SECRET_KEY, secret, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

export async function getTotpSecret(): Promise<string | null> {
  if (Platform.OS === 'web') {
    return webFallbackStore[TOTP_SECRET_KEY] ?? null;
  }
  return SecureStore.getItemAsync(TOTP_SECRET_KEY);
}

