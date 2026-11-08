import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';
import { Platform } from 'react-native';
import { getRefreshToken, clearRefreshToken } from '../storage/secureStorage';

/**
 * URL base del backend.
 * En emulador Android 10.0.2.2 apunta al localhost de la máquina host.
 * Se puede sobreescribir con EXPO_PUBLIC_API_URL o desde la interfaz de la app.
 */
const DEFAULT_BASE_URL =
  process.env.EXPO_PUBLIC_API_URL ||
  (Platform.OS === 'android' ? 'http://10.0.2.2:3000' : 'http://localhost:3000');

let currentBaseUrl = DEFAULT_BASE_URL;

export function getApiBaseUrl(): string {
  return currentBaseUrl;
}

export function setApiBaseUrl(url: string): void {
  currentBaseUrl = url.replace(/\/+$/, '');
  apiClient.defaults.baseURL = currentBaseUrl;
}

// ============================================================================
// Estrategia de Separación de Memoria:
// access_token vive ÚNICAMENTE en memoria volátil (RAM).
// ============================================================================
let volatileAccessToken: string | null = null;
let onTokenUpdatedCallback: ((newToken: string | null) => void) | null = null;
let onSessionExpiredCallback: (() => void) | null = null;

export function setVolatileAccessToken(token: string | null): void {
  volatileAccessToken = token;
  if (onTokenUpdatedCallback) {
    onTokenUpdatedCallback(token);
  }
}

export function getVolatileAccessToken(): string | null {
  return volatileAccessToken;
}

export function registerAuthListeners(listeners: {
  onTokenUpdated: (newToken: string | null) => void;
  onSessionExpired: () => void;
}): void {
  onTokenUpdatedCallback = listeners.onTokenUpdated;
  onSessionExpiredCallback = listeners.onSessionExpired;
}

// Instancia principal de Axios
export const apiClient = axios.create({
  baseURL: currentBaseUrl,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor de salida: adjunta el access_token desde memoria volátil
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  if (volatileAccessToken && config.headers) {
    config.headers.Authorization = `Bearer ${volatileAccessToken}`;
  }
  return config;
});

// ============================================================================
// Punto 2: Interceptor de Red con Cola Silenciosa (Silent Refresh Queue)
// ============================================================================
interface QueuedRequest {
  resolve: (token: string) => void;
  reject: (err: unknown) => void;
}

let isRefreshing = false;
let failedRequestsQueue: QueuedRequest[] = [];

function processQueue(error: unknown, newToken: string | null = null): void {
  failedRequestsQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else if (newToken) {
      prom.resolve(newToken);
    }
  });
  failedRequestsQueue = [];
}

interface RetryableRequestConfig extends InternalAxiosRequestConfig {
  _retry?: boolean;
}

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as RetryableRequestConfig | undefined;

    if (!originalRequest || !error.response) {
      return Promise.reject(error);
    }

    // Evitar interceptar endpoints de login/refresh/mfa directamente
    const isAuthEndpoint =
      originalRequest.url?.includes('/auth/refresh') ||
      originalRequest.url?.includes('/auth/oauth/token') ||
      originalRequest.url?.includes('/auth/mfa/verify');

    if (error.response.status === 401 && !originalRequest._retry && !isAuthEndpoint) {
      originalRequest._retry = true;

      // Si ya hay un refresh en curso, encolar esta petición en vuelo
      if (isRefreshing) {
        return new Promise<string>((resolve, reject) => {
          failedRequestsQueue.push({ resolve, reject });
        }).then((newToken) => {
          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
          }
          return apiClient(originalRequest);
        });
      }

      isRefreshing = true;

      try {
        const storedRefreshToken = await getRefreshToken();
        if (!storedRefreshToken) {
          throw new Error('No existe refresh_token en SecureStore');
        }

        // Disparar una única petición de renovación: POST /auth/refresh
        const refreshResponse = await axios.post(`${currentBaseUrl}/auth/refresh`, {
          refresh_token: storedRefreshToken,
        });

        const newAccessToken: string = refreshResponse.data.access_token;
        setVolatileAccessToken(newAccessToken);

        // Desbloquear todas las peticiones encoladas con el nuevo access_token
        processQueue(null, newAccessToken);

        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
        }
        return apiClient(originalRequest);
      } catch (refreshError) {
        // Si el refresh_token está vencido o revocado: limpiar SecureStore y volver a login
        processQueue(refreshError, null);
        setVolatileAccessToken(null);
        await clearRefreshToken();
        if (onSessionExpiredCallback) {
          onSessionExpiredCallback();
        }
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

