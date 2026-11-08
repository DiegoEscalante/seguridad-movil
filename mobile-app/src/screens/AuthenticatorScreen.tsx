import React, { useEffect, useState } from 'react';
import {
  Modal,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import {
  cleanBase32Secret,
  generateTOTP,
  isValidBase32Secret,
  parseOtpAuthUri,
} from '../crypto/totp';
import { getTotpSecret, saveTotpSecret } from '../storage/secureStorage';

const DEFAULT_LAB_SECRET = 'JBSWY3DPEHPK3PXP';

export const AuthenticatorScreen: React.FC = () => {
  const [secret, setSecret] = useState<string>(DEFAULT_LAB_SECRET);
  const [manualInput, setManualInput] = useState<string>(DEFAULT_LAB_SECRET);
  const [accountLabel, setAccountLabel] = useState<string>('UniSabana:estudiante@unisabana.edu.co');
  const [totpData, setTotpData] = useState(() => generateTOTP(DEFAULT_LAB_SECRET));
  const [inputError, setInputError] = useState<string | null>(null);
  const [scannerVisible, setScannerVisible] = useState(false);
  const [permission, requestPermission] = useCameraPermissions();

  useEffect(() => {
    (async () => {
      const saved = await getTotpSecret();
      if (saved && isValidBase32Secret(saved)) {
        setSecret(saved);
        setManualInput(saved);
        setTotpData(generateTOTP(saved));
      } else {
        await saveTotpSecret(DEFAULT_LAB_SECRET);
      }
    })();
  }, []);

  // Temporizador en tiempo real cada 250ms que recalcula matemáticamente en base a UnixTime // 30
  // Opera 100% offline (Modo Avión)
  useEffect(() => {
    const updateCode = () => {
      try {
        setTotpData(generateTOTP(secret));
      } catch {
        // Ignorar si la semilla está siendo editada
      }
    };
    updateCode();
    const interval = setInterval(updateCode, 250);
    return () => clearInterval(interval);
  }, [secret]);

  const handleApplyManualSecret = async () => {
    setInputError(null);
    const parsed = parseOtpAuthUri(manualInput);
    if (!parsed) {
      setInputError(
        'Semilla inválida. Ingresa una cadena Base32 válida (A-Z, 2-7) o un URI otpauth://totp/...'
      );
      return;
    }
    const clean = cleanBase32Secret(parsed.secret);
    setSecret(clean);
    setManualInput(clean);
    if (parsed.label) {
      setAccountLabel(parsed.label);
    }
    await saveTotpSecret(clean);
  };

  const handleOpenScanner = async () => {
    setInputError(null);
    if (!permission?.granted) {
      const res = await requestPermission();
      if (!res.granted) {
        setInputError('Permiso de cámara denegado. Usa la entrada manual Base32.');
        return;
      }
    }
    setScannerVisible(true);
  };

  const handleBarcodeScanned = async ({ data }: { data: string }) => {
    setScannerVisible(false);
    const parsed = parseOtpAuthUri(data);
    if (!parsed) {
      setInputError(`El código QR escaneado no contiene un secreto TOTP válido: ${data}`);
      return;
    }
    setSecret(parsed.secret);
    setManualInput(parsed.secret);
    if (parsed.label) {
      setAccountLabel(parsed.label);
    }
    await saveTotpSecret(parsed.secret);
  };

  const progressPercent = (totpData.remainingSeconds / 30) * 100;
  const formattedCode = `${totpData.code.slice(0, 3)} ${totpData.code.slice(3, 6)}`;

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <View style={styles.headerRow}>
        <View style={styles.offlineBadge}>
          <Text style={styles.offlineBadgeText}>100% OFFLINE · MODO AVIÓN READY</Text>
        </View>
        <Text style={styles.rfcTag}>RFC 6238 (HMAC-SHA1)</Text>
      </View>

      <View style={styles.codeCard}>
        <Text style={styles.accountLabel}>{accountLabel}</Text>
        <Text style={styles.totpDigits}>{formattedCode}</Text>

        <View style={styles.progressTrack}>
          <View
            style={[
              styles.progressFill,
              {
                width: `${progressPercent}%`,
                backgroundColor: totpData.remainingSeconds <= 5 ? '#ef4444' : '#3b82f6',
              },
            ]}
          />
        </View>

        <View style={styles.timerFooter}>
          <Text style={styles.timerText}>
            Renueva en <Text style={styles.timerHighlight}>{totpData.remainingSeconds}s</Text>
          </Text>
          <Text style={styles.stepText}>Ventana T = {totpData.timeStep}</Text>
        </View>
      </View>

      <View style={styles.configCard}>
        <Text style={styles.sectionTitle}>Ingesta del Secreto (Semilla Base32 o QR)</Text>
        <Text style={styles.sectionSubtitle}>
          Puedes escanear un QR con formato otpauth://totp/... o pegar manualmente la semilla Base32
          para verificar paridad con Google Authenticator.
        </Text>

        <TextInput
          style={styles.input}
          value={manualInput}
          onChangeText={setManualInput}
          autoCapitalize="characters"
          autoCorrect={false}
          placeholder="JBSWY3DPEHPK3PXP o otpauth://totp/..."
          placeholderTextColor="#64748b"
        />

        {inputError && <Text style={styles.errorText}>{inputError}</Text>}

        <View style={styles.buttonRow}>
          <TouchableOpacity style={styles.primaryBtn} onPress={handleApplyManualSecret}>
            <Text style={styles.primaryBtnText}>Guardar Semilla</Text>
          </TouchableOpacity>

          <TouchableOpacity style={styles.secondaryBtn} onPress={handleOpenScanner}>
            <Text style={styles.secondaryBtnText}>Escanear QR</Text>
          </TouchableOpacity>
        </View>
      </View>

      <Modal visible={scannerVisible} animationType="slide">
        <View style={styles.modalContainer}>
          <CameraView
            style={styles.camera}
            facing="back"
            barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
            onBarcodeScanned={handleBarcodeScanned}
          />
          <View style={styles.scannerOverlay}>
            <Text style={styles.scannerTitle}>Apunta al código QR TOTP (otpauth://)</Text>
            <TouchableOpacity
              style={styles.closeScannerBtn}
              onPress={() => setScannerVisible(false)}
            >
              <Text style={styles.closeScannerText}>Cancelar</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 18,
  },
  headerRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 14,
  },
  offlineBadge: {
    backgroundColor: '#064e3b',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 999,
    borderWidth: 1,
    borderColor: '#10b981',
  },
  offlineBadgeText: {
    color: '#6ee7b7',
    fontSize: 11,
    fontWeight: '700',
  },
  rfcTag: {
    color: '#94a3b8',
    fontSize: 12,
    fontFamily: 'monospace',
  },
  codeCard: {
    backgroundColor: '#1e293b',
    borderRadius: 18,
    padding: 22,
    borderWidth: 1,
    borderColor: '#334155',
    alignItems: 'center',
    marginBottom: 18,
  },
  accountLabel: {
    color: '#94a3b8',
    fontSize: 13,
    marginBottom: 10,
  },
  totpDigits: {
    color: '#f8fafc',
    fontSize: 44,
    fontWeight: '800',
    fontFamily: 'monospace',
    letterSpacing: 4,
    marginBottom: 18,
  },
  progressTrack: {
    width: '100%',
    height: 8,
    backgroundColor: '#0f172a',
    borderRadius: 999,
    overflow: 'hidden',
    marginBottom: 12,
  },
  progressFill: {
    height: '100%',
    borderRadius: 999,
  },
  timerFooter: {
    width: '100%',
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  timerText: {
    color: '#cbd5e1',
    fontSize: 13,
  },
  timerHighlight: {
    color: '#38bdf8',
    fontWeight: '700',
  },
  stepText: {
    color: '#64748b',
    fontSize: 12,
    fontFamily: 'monospace',
  },
  configCard: {
    backgroundColor: '#1e293b',
    borderRadius: 16,
    padding: 18,
    borderWidth: 1,
    borderColor: '#334155',
  },
  sectionTitle: {
    color: '#f8fafc',
    fontSize: 16,
    fontWeight: '700',
    marginBottom: 6,
  },
  sectionSubtitle: {
    color: '#94a3b8',
    fontSize: 13,
    lineHeight: 18,
    marginBottom: 14,
  },
  input: {
    backgroundColor: '#0f172a',
    borderWidth: 1,
    borderColor: '#475569',
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 11,
    color: '#f8fafc',
    fontFamily: 'monospace',
    fontSize: 14,
    marginBottom: 12,
  },
  errorText: {
    color: '#f87171',
    fontSize: 12,
    marginBottom: 10,
  },
  buttonRow: {
    flexDirection: 'row',
    gap: 10,
  },
  primaryBtn: {
    flex: 1,
    backgroundColor: '#2563eb',
    paddingVertical: 12,
    borderRadius: 10,
    alignItems: 'center',
  },
  primaryBtnText: {
    color: '#ffffff',
    fontWeight: '700',
    fontSize: 14,
  },
  secondaryBtn: {
    flex: 1,
    backgroundColor: '#0f172a',
    borderWidth: 1,
    borderColor: '#3b82f6',
    paddingVertical: 12,
    borderRadius: 10,
    alignItems: 'center',
  },
  secondaryBtnText: {
    color: '#60a5fa',
    fontWeight: '700',
    fontSize: 14,
  },
  modalContainer: {
    flex: 1,
    backgroundColor: '#000',
  },
  camera: {
    flex: 1,
  },
  scannerOverlay: {
    position: 'absolute',
    bottom: 40,
    left: 20,
    right: 20,
    backgroundColor: 'rgba(15, 23, 42, 0.9)',
    padding: 20,
    borderRadius: 16,
    alignItems: 'center',
  },
  scannerTitle: {
    color: '#f8fafc',
    fontSize: 15,
    fontWeight: '600',
    marginBottom: 14,
  },
  closeScannerBtn: {
    backgroundColor: '#ef4444',
    paddingHorizontal: 24,
    paddingVertical: 10,
    borderRadius: 8,
  },
  closeScannerText: {
    color: '#fff',
    fontWeight: '700',
  },
});

