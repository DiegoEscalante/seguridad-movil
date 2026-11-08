import React, { useState } from 'react';
import {
  ActivityIndicator,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import { getApiBaseUrl, setApiBaseUrl } from '../api/apiClient';
import { useAuth } from '../context/AuthContext';

export const LoginScreen: React.FC = () => {
  const { startOAuthPkceLogin } = useAuth();
  const [serverUrl, setServerUrl] = useState(getApiBaseUrl());
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleLogin = async () => {
    setErrorMsg(null);
    setLoading(true);
    try {
      setApiBaseUrl(serverUrl.trim());
      await startOAuthPkceLogin();
    } catch (err: any) {
      const msg =
        err?.response?.data?.message ||
        err?.message ||
        'Error al ejecutar el flujo OAuth 2.0 + PKCE';
      setErrorMsg(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <View style={styles.container}>
      <View style={styles.badge}>
        <Text style={styles.badgeText}>RFC 7636 · OAuth 2.0 + PKCE</Text>
      </View>

      <Text style={styles.title}>Seguridad Móvil UniSabana</Text>
      <Text style={styles.subtitle}>
        Autenticación delegada al navegador seguro del sistema (WebBrowser), almacenamiento
        en Keychain/Keystore y Step-Up 2FA con TOTP offline.
      </Text>

      <View style={styles.card}>
        <Text style={styles.label}>URL del Backend de Autenticación</Text>
        <TextInput
          style={styles.input}
          value={serverUrl}
          onChangeText={setServerUrl}
          autoCapitalize="none"
          autoCorrect={false}
          placeholder="http://192.168.1.X:3000"
          placeholderTextColor="#64748b"
        />
        <Text style={styles.helper}>
          En emulador iOS/Web usa localhost:3000, en Android 10.0.2.2:3000 o la IP LAN de tu PC.
        </Text>

        {errorMsg && (
          <View style={styles.errorBox}>
            <Text style={styles.errorText}>{errorMsg}</Text>
          </View>
        )}

        <TouchableOpacity
          style={[styles.primaryButton, loading && styles.disabledButton]}
          onPress={handleLogin}
          disabled={loading}
        >
          {loading ? (
            <ActivityIndicator color="#ffffff" />
          ) : (
            <Text style={styles.primaryButtonText}>
              Iniciar Sesión con Navegador Seguro
            </Text>
          )}
        </TouchableOpacity>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    justifyContent: 'center',
  },
  badge: {
    alignSelf: 'flex-start',
    backgroundColor: '#1e3a8a',
    paddingHorizontal: 12,
    paddingVertical: 5,
    borderRadius: 999,
    marginBottom: 12,
  },
  badgeText: {
    color: '#93c5fd',
    fontSize: 12,
    fontWeight: '700',
  },
  title: {
    fontSize: 26,
    fontWeight: '800',
    color: '#f8fafc',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 14,
    color: '#94a3b8',
    lineHeight: 20,
    marginBottom: 24,
  },
  card: {
    backgroundColor: '#1e293b',
    borderRadius: 16,
    padding: 20,
    borderWidth: 1,
    borderColor: '#334155',
  },
  label: {
    fontSize: 13,
    fontWeight: '600',
    color: '#cbd5e1',
    marginBottom: 8,
  },
  input: {
    backgroundColor: '#0f172a',
    borderWidth: 1,
    borderColor: '#475569',
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 11,
    color: '#f8fafc',
    fontSize: 14,
    fontFamily: 'monospace',
  },
  helper: {
    fontSize: 12,
    color: '#64748b',
    marginTop: 6,
    marginBottom: 18,
  },
  errorBox: {
    backgroundColor: '#450a0a',
    borderColor: '#dc2626',
    borderWidth: 1,
    borderRadius: 10,
    padding: 12,
    marginBottom: 16,
  },
  errorText: {
    color: '#fca5a5',
    fontSize: 13,
  },
  primaryButton: {
    backgroundColor: '#2563eb',
    borderRadius: 12,
    paddingVertical: 15,
    alignItems: 'center',
  },
  disabledButton: {
    opacity: 0.6,
  },
  primaryButtonText: {
    color: '#ffffff',
    fontSize: 15,
    fontWeight: '700',
  },
});

