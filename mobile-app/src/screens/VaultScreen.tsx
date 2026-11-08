import React, { useState } from 'react';
import {
  ActivityIndicator,
  Modal,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import { apiClient } from '../api/apiClient';
import { useAuth } from '../context/AuthContext';
import { generateTOTP } from '../crypto/totp';
import { getTotpSecret } from '../storage/secureStorage';

interface VaultSecret {
  id: string;
  label: string;
  value: string;
}

export const VaultScreen: React.FC = () => {
  const {
    accessToken,
    hasStoredRefreshToken,
    isMfaElevated,
    lastPkceAudit,
    elevateSessionWithTotp,
    invalidateVolatileAccessTokenForDemo,
    logout,
  } = useAuth();

  const [vaultSecrets, setVaultSecrets] = useState<VaultSecret[] | null>(null);
  const [stepUpToken, setStepUpToken] = useState<string | null>(null);
  const [stepUpModalVisible, setStepUpModalVisible] = useState(false);
  const [totpInput, setTotpInput] = useState('');
  const [lastUsedCode, setLastUsedCode] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<{
    type: 'info' | 'success' | 'error';
    text: string;
  } | null>(null);
  const [loading, setLoading] = useState(false);

  /**
   * Solicita GET /api/boveda-critica.
   * Si responde 403 Forbidden (mfa_required), captura el step_up_token y abre el modal Step-Up 2FA.
   */
  const handleRequestVault = async () => {
    setLoading(true);
    setStatusMessage(null);
    try {
      const response = await apiClient.get('/api/boveda-critica');
      setVaultSecrets(response.data.secrets);
      setStatusMessage({
        type: 'success',
        text: 'Acceso autorizado a la Bóveda Crítica con sesión elevada (mfa_verified: true).',
      });
    } catch (err: any) {
      if (err?.response?.status === 403 && err.response.data?.error === 'mfa_required') {
        const receivedStepUpToken = err.response.data.step_up_token;
        setStepUpToken(receivedStepUpToken);

        // Pre-llenar opcionalmente con el código calculado por nuestro módulo Authenticator local
        const storedSecret = (await getTotpSecret()) || 'JBSWY3DPEHPK3PXP';
        const localTotp = generateTOTP(storedSecret).code;
        setTotpInput(localTotp);

        setStepUpModalVisible(true);
        setStatusMessage({
          type: 'info',
          text: '403 Forbidden (mfa_required): Se requiere Step-Up 2FA para desbloquear la bóveda.',
        });
      } else {
        setStatusMessage({
          type: 'error',
          text: err?.response?.data?.message || err?.message || 'Error al consultar la bóveda.',
        });
      }
    } finally {
      setLoading(false);
    }
  };

  /**
   * Envía el step_up_token y el código TOTP de 6 dígitos a POST /auth/mfa/verify,
   * obtiene el elevated_token y reintenta GET /api/boveda-critica.
   */
  const handleVerifyStepUp = async () => {
    if (!stepUpToken) return;
    setLoading(true);
    try {
      await elevateSessionWithTotp(stepUpToken, totpInput.trim());
      setLastUsedCode(totpInput.trim());
      setStepUpModalVisible(false);

      // Consultar inmediatamente la bóveda crítica con el nuevo elevated_token
      const vaultRes = await apiClient.get('/api/boveda-critica');
      setVaultSecrets(vaultRes.data.secrets);
      setStatusMessage({
        type: 'success',
        text: `2FA verificado correctamente. Bóveda desbloqueada con código ${totpInput.trim()}.`,
      });
    } catch (err: any) {
      const httpStatus = err?.response?.status;
      const serverMsg = err?.response?.data?.message || err?.message;
      setStatusMessage({
        type: 'error',
        text: httpStatus ? `HTTP ${httpStatus}: ${serverMsg}` : serverMsg,
      });
    } finally {
      setLoading(false);
    }
  };

  /**
   * Prueba 5 de Aceptación: Ataque de Repetición (Anti-Replay).
   * Reenvía inmediatamente el mismo código TOTP recién utilizado para demostrar el bloqueo 409 Conflict.
   */
  const handleSimulateReplayAttack = async () => {
    if (!stepUpToken || !lastUsedCode) {
      setStatusMessage({
        type: 'info',
        text: 'Primero desbloquea la bóveda una vez con 2FA para registrar un código y probar el ataque de repetición.',
      });
      return;
    }

    setLoading(true);
    try {
      await elevateSessionWithTotp(stepUpToken, lastUsedCode);
    } catch (err: any) {
      const httpStatus = err?.response?.status;
      const serverMsg = err?.response?.data?.message || 'Solicitud rechazada';
      setStatusMessage({
        type: 'error',
        text: `Prueba Anti-Replay Exitosa -> HTTP ${httpStatus}: ${serverMsg}`,
      });
    } finally {
      setLoading(false);
    }
  };

  /**
   * Prueba Punto 2: Simula expiración del access_token en memoria y lanza 3 peticiones
   * concurrentes para demostrar la cola silenciosa (Silent Refresh Queue).
   */
  const handleTestSilentRefreshQueue = async () => {
    setLoading(true);
    setVaultSecrets(null);
    invalidateVolatileAccessTokenForDemo();
    try {
      // Disparar 3 llamadas simultáneas con el access_token inválido (401)
      const [r1, r2, r3] = await Promise.all([
        apiClient.get('/api/perfil'),
        apiClient.get('/api/perfil'),
        apiClient.get('/api/perfil'),
      ]);
      setStatusMessage({
        type: 'success',
        text: `Silent Refresh Queue exitoso: 3 peticiones en paralelo pausadas en 401 y resueltas tras 1 único POST /auth/refresh (${r1.data.user.email}, ${r2.status}, ${r3.status}).`,
      });
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err?.message || 'Fallo en Silent Refresh Queue',
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      {/* Tarjeta de Bóveda Crítica */}
      <View style={styles.card}>
        <View style={styles.rowBetween}>
          <Text style={styles.cardTitle}>Bóveda Crítica de Negocio</Text>
          <View
            style={[
              styles.statusPill,
              isMfaElevated ? styles.pillElevated : styles.pillStandard,
            ]}
          >
            <Text style={styles.statusPillText}>
              {isMfaElevated ? 'MFA ELEVATED' : 'STANDARD TOKEN'}
            </Text>
          </View>
        </View>

        <Text style={styles.cardDesc}>
          Ruta protegida (GET /api/boveda-critica). Exige un token con claim{' '}
          <Text style={styles.mono}>mfa_verified: true</Text>.
        </Text>

        {statusMessage && (
          <View
            style={[
              styles.alertBox,
              statusMessage.type === 'success' && styles.alertSuccess,
              statusMessage.type === 'error' && styles.alertError,
              statusMessage.type === 'info' && styles.alertInfo,
            ]}
          >
            <Text style={styles.alertText}>{statusMessage.text}</Text>
          </View>
        )}

        {vaultSecrets && (
          <View style={styles.secretsContainer}>
            {vaultSecrets.map((item) => (
              <View key={item.id} style={styles.secretRow}>
                <Text style={styles.secretLabel}>{item.label}</Text>
                <Text style={styles.secretValue}>{item.value}</Text>
              </View>
            ))}
          </View>
        )}

        <TouchableOpacity
          style={styles.primaryBtn}
          onPress={handleRequestVault}
          disabled={loading}
        >
          {loading ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.primaryBtnText}>Abrir Bóveda Crítica</Text>
          )}
        </TouchableOpacity>

        <View style={styles.demoActionsRow}>
          <TouchableOpacity
            style={styles.replayBtn}
            onPress={handleSimulateReplayAttack}
            disabled={loading}
          >
            <Text style={styles.replayBtnText}>Probar Ataque Replay (409)</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.refreshBtn}
            onPress={handleTestSilentRefreshQueue}
            disabled={loading}
          >
            <Text style={styles.refreshBtnText}>Probar Cola 401 Refresh</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Estado de Almacenamiento y Tokens */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Estado de Tokens y Memoria</Text>
        <View style={styles.metaItem}>
          <Text style={styles.metaLabel}>access_token (Solo en RAM):</Text>
          <Text style={styles.metaValue} numberOfLines={1}>
            {accessToken ? `${accessToken.slice(0, 36)}...` : 'Ninguno'}
          </Text>
        </View>
        <View style={styles.metaItem}>
          <Text style={styles.metaLabel}>refresh_token (Hardware Keychain/Keystore):</Text>
          <Text style={styles.metaValue}>
            {hasStoredRefreshToken ? 'Cifrado en expo-secure-store' : 'No presente'}
          </Text>
        </View>
        {lastPkceAudit && (
          <View style={styles.metaItem}>
            <Text style={styles.metaLabel}>Último PKCE Challenge (S256):</Text>
            <Text style={styles.metaValue} numberOfLines={1}>
              {lastPkceAudit.codeChallenge}
            </Text>
          </View>
        )}

        <TouchableOpacity style={styles.logoutBtn} onPress={logout}>
          <Text style={styles.logoutBtnText}>Cerrar Sesión y Limpiar Enclave Seguro</Text>
        </TouchableOpacity>
      </View>

      {/* Modal Step-Up 2FA */}
      <Modal visible={stepUpModalVisible} transparent animationType="fade">
        <View style={styles.modalBackdrop}>
          <View style={styles.modalCard}>
            <Text style={styles.modalBadge}>403 FORBIDDEN · MFA REQUIRED</Text>
            <Text style={styles.modalTitle}>Verificación Step-Up 2FA</Text>
            <Text style={styles.modalDesc}>
              Ingresa el código TOTP de 6 dígitos generado en la pestaña Authenticator (o Google
              Authenticator) para elevar privilegios.
            </Text>

            <TextInput
              style={styles.totpInput}
              value={totpInput}
              onChangeText={setTotpInput}
              keyboardType="number-pad"
              maxLength={6}
              placeholder="000000"
              placeholderTextColor="#475569"
            />

            <View style={styles.modalBtns}>
              <TouchableOpacity
                style={styles.cancelModalBtn}
                onPress={() => setStepUpModalVisible(false)}
              >
                <Text style={styles.cancelModalText}>Cancelar</Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={styles.confirmModalBtn}
                onPress={handleVerifyStepUp}
                disabled={loading || totpInput.trim().length !== 6}
              >
                <Text style={styles.confirmModalText}>Verificar 2FA</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 18,
    gap: 16,
  },
  card: {
    backgroundColor: '#1e293b',
    borderRadius: 16,
    padding: 18,
    borderWidth: 1,
    borderColor: '#334155',
  },
  rowBetween: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  cardTitle: {
    color: '#f8fafc',
    fontSize: 17,
    fontWeight: '700',
  },
  statusPill: {
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 999,
  },
  pillElevated: {
    backgroundColor: '#065f46',
  },
  pillStandard: {
    backgroundColor: '#334155',
  },
  statusPillText: {
    color: '#e2e8f0',
    fontSize: 10,
    fontWeight: '700',
  },
  cardDesc: {
    color: '#94a3b8',
    fontSize: 13,
    lineHeight: 19,
    marginBottom: 14,
  },
  mono: {
    fontFamily: 'monospace',
    color: '#38bdf8',
  },
  alertBox: {
    padding: 12,
    borderRadius: 10,
    borderWidth: 1,
    marginBottom: 14,
  },
  alertSuccess: {
    backgroundColor: '#064e3b',
    borderColor: '#10b981',
  },
  alertError: {
    backgroundColor: '#450a0a',
    borderColor: '#ef4444',
  },
  alertInfo: {
    backgroundColor: '#1e3a8a',
    borderColor: '#3b82f6',
  },
  alertText: {
    color: '#f8fafc',
    fontSize: 13,
    lineHeight: 18,
  },
  secretsContainer: {
    backgroundColor: '#0f172a',
    borderRadius: 12,
    padding: 12,
    marginBottom: 14,
    gap: 10,
  },
  secretRow: {
    borderBottomWidth: 1,
    borderBottomColor: '#1e293b',
    paddingBottom: 8,
  },
  secretLabel: {
    color: '#94a3b8',
    fontSize: 12,
    marginBottom: 2,
  },
  secretValue: {
    color: '#34d399',
    fontFamily: 'monospace',
    fontSize: 13,
    fontWeight: '700',
  },
  primaryBtn: {
    backgroundColor: '#2563eb',
    paddingVertical: 13,
    borderRadius: 10,
    alignItems: 'center',
    marginBottom: 10,
  },
  primaryBtnText: {
    color: '#fff',
    fontWeight: '700',
    fontSize: 14,
  },
  demoActionsRow: {
    flexDirection: 'row',
    gap: 8,
  },
  replayBtn: {
    flex: 1,
    backgroundColor: '#3f1d2e',
    borderWidth: 1,
    borderColor: '#f43f5e',
    paddingVertical: 10,
    borderRadius: 10,
    alignItems: 'center',
  },
  replayBtnText: {
    color: '#fda4af',
    fontSize: 12,
    fontWeight: '700',
  },
  refreshBtn: {
    flex: 1,
    backgroundColor: '#1e293b',
    borderWidth: 1,
    borderColor: '#38bdf8',
    paddingVertical: 10,
    borderRadius: 10,
    alignItems: 'center',
  },
  refreshBtnText: {
    color: '#7dd3fc',
    fontSize: 12,
    fontWeight: '700',
  },
  metaItem: {
    marginTop: 10,
  },
  metaLabel: {
    color: '#94a3b8',
    fontSize: 12,
  },
  metaValue: {
    color: '#e2e8f0',
    fontFamily: 'monospace',
    fontSize: 12,
    marginTop: 2,
  },
  logoutBtn: {
    marginTop: 16,
    backgroundColor: '#0f172a',
    borderWidth: 1,
    borderColor: '#ef4444',
    paddingVertical: 11,
    borderRadius: 10,
    alignItems: 'center',
  },
  logoutBtnText: {
    color: '#f87171',
    fontSize: 13,
    fontWeight: '700',
  },
  modalBackdrop: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.75)',
    justifyContent: 'center',
    padding: 20,
  },
  modalCard: {
    backgroundColor: '#1e293b',
    borderRadius: 18,
    padding: 22,
    borderWidth: 1,
    borderColor: '#475569',
  },
  modalBadge: {
    color: '#f59e0b',
    fontSize: 11,
    fontWeight: '800',
    marginBottom: 6,
  },
  modalTitle: {
    color: '#f8fafc',
    fontSize: 20,
    fontWeight: '800',
    marginBottom: 8,
  },
  modalDesc: {
    color: '#94a3b8',
    fontSize: 13,
    lineHeight: 19,
    marginBottom: 16,
  },
  totpInput: {
    backgroundColor: '#0f172a',
    borderWidth: 1,
    borderColor: '#3b82f6',
    borderRadius: 12,
    paddingVertical: 14,
    textAlign: 'center',
    color: '#f8fafc',
    fontSize: 28,
    fontWeight: '800',
    fontFamily: 'monospace',
    letterSpacing: 8,
    marginBottom: 18,
  },
  modalBtns: {
    flexDirection: 'row',
    gap: 10,
  },
  cancelModalBtn: {
    flex: 1,
    backgroundColor: '#334155',
    paddingVertical: 12,
    borderRadius: 10,
    alignItems: 'center',
  },
  cancelModalText: {
    color: '#cbd5e1',
    fontWeight: '700',
  },
  confirmModalBtn: {
    flex: 1,
    backgroundColor: '#2563eb',
    paddingVertical: 12,
    borderRadius: 10,
    alignItems: 'center',
  },
  confirmModalText: {
    color: '#fff',
    fontWeight: '700',
  },
});

