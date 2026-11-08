import React, { createContext, useContext, useEffect, useState } from 'react';
import * as WebBrowser from 'expo-web-browser';
import * as Linking from 'expo-linking';
import {
  apiClient,
  getApiBaseUrl,
  registerAuthListeners,
  setVolatileAccessToken,
} from '../api/apiClient';
import {
  generateAntiCsrfState,
  generateCodeChallenge,
  generateCodeVerifier,
} from '../crypto/pkce';
import {
  clearRefreshToken,
  getRefreshToken,
  saveRefreshToken,
} from '../storage/secureStorage';

WebBrowser.maybeCompleteAuthSession();

export interface UserProfile {
  id: string;
  email: string;
  name: string;
}

interface AuthContextValue {
  accessToken: string | null;
  hasStoredRefreshToken: boolean;
  user: UserProfile | null;
  isMfaElevated: boolean;
  isLoading: boolean;
  lastPkceAudit: {
    codeVerifier: string;
    codeChallenge: string;
    state: string;
    redirectUri: string;
  } | null;
  startOAuthPkceLogin: () => Promise<void>;
  elevateSessionWithTotp: (stepUpToken: string, totpCode: string) => Promise<void>;
  invalidateVolatileAccessTokenForDemo: () => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [accessToken, setAccessTokenState] = useState<string | null>(null);
  const [hasStoredRefreshToken, setHasStoredRefreshToken] = useState(false);
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isMfaElevated, setIsMfaElevated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [lastPkceAudit, setLastPkceAudit] = useState<AuthContextValue['lastPkceAudit']>(null);

  useEffect(() => {
    registerAuthListeners({
      onTokenUpdated: (newToken) => {
        setAccessTokenState(newToken);
      },
      onSessionExpired: () => {
        setAccessTokenState(null);
        setHasStoredRefreshToken(false);
        setUser(null);
        setIsMfaElevated(false);
      },
    });

    // Al iniciar la app, verificar si hay un refresh_token en SecureStore y renovar silenciosamente
    (async () => {
      try {
        const storedRt = await getRefreshToken();
        if (storedRt) {
          setHasStoredRefreshToken(true);
          const response = await apiClient.post('/auth/refresh', {
            refresh_token: storedRt,
          });
          setVolatileAccessToken(response.data.access_token);
          const profileRes = await apiClient.get('/api/perfil');
          setUser(profileRes.data.user);
        }
      } catch {
        await clearRefreshToken();
        setHasStoredRefreshToken(false);
      } finally {
        setIsLoading(false);
      }
    })();
  }, []);

  /**
   * Punto 1: Flujo OAuth 2.0 con PKCE desde la App Móvil (RFC 7636)
   * Soporta de forma nativa tanto Expo Go (exp://...) como compilación standalone (unisabana-auth://callback)
   */
  const startOAuthPkceLogin = async () => {
    const codeVerifier = generateCodeVerifier(64);
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    const expectedState = generateAntiCsrfState(32);

    // Generamos el Deep Link con el esquema configurado en app.json (unisabana-auth://callback)
    const redirectUri = 'unisabana-auth://callback';

    setLastPkceAudit({
      codeVerifier,
      codeChallenge,
      state: expectedState,
      redirectUri,
    });

    const authorizeUrl =
      `${getApiBaseUrl()}/oauth/authorize` +
      `?response_type=code` +
      `&client_id=unisabana-mobile` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&code_challenge=${encodeURIComponent(codeChallenge)}` +
      `&code_challenge_method=S256` +
      `&state=${encodeURIComponent(expectedState)}`;

    // En Android + Expo Go, escuchamos tanto el Deep Link directo como el estado de autorización
    // para cerrar el navegador automáticamente en cuanto el usuario presiona "Autorizar".
    let capturedCallbackUrl: string | null = null;
    const subscription = Linking.addEventListener('url', (event) => {
      if (event.url && event.url.includes('code=')) {
        capturedCallbackUrl = event.url;
        WebBrowser.dismissAuthSession();
      }
    });

    const pollInterval = setInterval(async () => {
      try {
        const pollRes = await apiClient.get(`/oauth/poll/${encodeURIComponent(expectedState)}`);
        if (pollRes.data?.authorized && pollRes.data?.redirectUrl) {
          capturedCallbackUrl = pollRes.data.redirectUrl;
          clearInterval(pollInterval);
          WebBrowser.dismissAuthSession();
        }
      } catch {
        // Ignorar errores de red durante el polling
      }
    }, 600);

    let result: WebBrowser.WebBrowserAuthSessionResult;
    try {
      // Abrir navegador seguro del sistema (NO WebView embebida)
      result = await WebBrowser.openAuthSessionAsync(authorizeUrl, redirectUri);
    } finally {
      clearInterval(pollInterval);
      subscription.remove();
    }

    if (!capturedCallbackUrl && !(result.type === 'success' && result.url)) {
      try {
        const finalPoll = await apiClient.get(`/oauth/poll/${encodeURIComponent(expectedState)}`);
        if (finalPoll.data?.authorized && finalPoll.data?.redirectUrl) {
          capturedCallbackUrl = finalPoll.data.redirectUrl;
        }
      } catch {
        // Ignorar
      }
    }

    const finalUrl =
      result.type === 'success' && result.url ? result.url : capturedCallbackUrl;

    if (!finalUrl) {
      throw new Error('Autenticación cancelada en el navegador del sistema.');
    }

    const parsed = Linking.parse(finalUrl);
    let returnedCode = parsed.queryParams?.code as string | undefined;
    let returnedState = parsed.queryParams?.state as string | undefined;

    // Fallback de parseo manual por si la URL tiene formato custom
    if ((!returnedCode || !returnedState) && finalUrl.includes('?')) {
      const searchParams = new URLSearchParams(finalUrl.split('?')[1]);
      returnedCode = returnedCode || searchParams.get('code') || undefined;
      returnedState = returnedState || searchParams.get('state') || undefined;
    }

    // Protección Anti-CSRF: validar el parámetro state
    if (!returnedState || returnedState !== expectedState) {
      throw new Error('Alerta de Seguridad (CSRF): El parámetro state recibido no coincide con el generado.');
    }

    if (!returnedCode) {
      throw new Error('No se recibió authorization_code en el callback.');
    }

    // Token Exchange: enviar authorization_code + code_verifier a POST /auth/oauth/token
    const tokenResponse = await apiClient.post('/auth/oauth/token', {
      code: returnedCode,
      code_verifier: codeVerifier,
    });

    const { access_token, refresh_token, user: userInfo } = tokenResponse.data;

    // access_token en memoria volátil (RAM)
    setVolatileAccessToken(access_token);
    setIsMfaElevated(false);
    setUser(userInfo);

    // refresh_token en SecureStore (Keychain / Keystore)
    await saveRefreshToken(refresh_token);
    setHasStoredRefreshToken(true);
  };

  /**
   * Punto 4: Elevación de privilegios Step-Up con verificación TOTP
   */
  const elevateSessionWithTotp = async (stepUpToken: string, totpCode: string) => {
    const response = await apiClient.post('/auth/mfa/verify', {
      step_up_token: stepUpToken,
      code: totpCode,
    });

    const { elevated_token } = response.data;
    setVolatileAccessToken(elevated_token);
    setIsMfaElevated(true);
  };

  /**
   * Utilidad para la sustentación: corrompe el access_token en RAM para forzar un 401
   * y demostrar en vivo el Silent Refresh Queue con peticiones concurrentes.
   */
  const invalidateVolatileAccessTokenForDemo = () => {
    setVolatileAccessToken('expired_or_corrupted_token_for_401_demo');
    setIsMfaElevated(false);
  };

  const logout = async () => {
    setVolatileAccessToken(null);
    await clearRefreshToken();
    setHasStoredRefreshToken(false);
    setUser(null);
    setIsMfaElevated(false);
  };

  return (
    <AuthContext.Provider
      value={{
        accessToken,
        hasStoredRefreshToken,
        user,
        isMfaElevated,
        isLoading,
        lastPkceAudit,
        startOAuthPkceLogin,
        elevateSessionWithTotp,
        invalidateVolatileAccessTokenForDemo,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth debe usarse dentro de un AuthProvider');
  }
  return ctx;
}

