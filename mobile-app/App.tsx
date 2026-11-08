import React, { useState } from 'react';
import {
  ActivityIndicator,
  SafeAreaView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { AuthProvider, useAuth } from './src/context/AuthContext';
import { LoginScreen } from './src/screens/LoginScreen';
import { AuthenticatorScreen } from './src/screens/AuthenticatorScreen';
import { VaultScreen } from './src/screens/VaultScreen';

type ActiveTab = 'auth_vault' | 'totp_offline';

const MainShell: React.FC = () => {
  const { accessToken, user, isLoading } = useAuth();
  const [activeTab, setActiveTab] = useState<ActiveTab>('auth_vault');

  if (isLoading) {
    return (
      <View style={styles.centered}>
        <ActivityIndicator size="large" color="#3b82f6" />
      </View>
    );
  }

  return (
    <SafeAreaView style={styles.safeArea}>
      <StatusBar style="light" />

      {/* Barra de navegación superior siempre disponible (permite usar Authenticator en Modo Avión sin red) */}
      <View style={styles.topHeader}>
        <View>
          <Text style={styles.appTitle}>Compass · Seguridad Móvil</Text>
          <Text style={styles.appSubtitle}>
            {user ? `Sesión: ${user.email}` : 'Sin sesión activa (Modo Offline disponible)'}
          </Text>
        </View>
      </View>

      <View style={styles.tabBar}>
        <TouchableOpacity
          style={[styles.tabButton, activeTab === 'auth_vault' && styles.tabButtonActive]}
          onPress={() => setActiveTab('auth_vault')}
        >
          <Text
            style={[styles.tabText, activeTab === 'auth_vault' && styles.tabTextActive]}
          >
            {accessToken ? 'Bóveda & Tokens' : '1. Login OAuth + PKCE'}
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[
            styles.tabButton,
            activeTab === 'totp_offline' && styles.tabButtonActive,
          ]}
          onPress={() => setActiveTab('totp_offline')}
        >
          <Text
            style={[styles.tabText, activeTab === 'totp_offline' && styles.tabTextActive]}
          >
            2. Authenticator TOTP
          </Text>
        </TouchableOpacity>
      </View>

      <View style={styles.content}>
        {activeTab === 'totp_offline' ? (
          <AuthenticatorScreen />
        ) : accessToken ? (
          <VaultScreen />
        ) : (
          <LoginScreen />
        )}
      </View>
    </SafeAreaView>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <MainShell />
    </AuthProvider>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: '#0f172a',
  },
  centered: {
    flex: 1,
    backgroundColor: '#0f172a',
    justifyContent: 'center',
    alignItems: 'center',
  },
  topHeader: {
    paddingHorizontal: 18,
    paddingTop: 14,
    paddingBottom: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#1e293b',
  },
  appTitle: {
    color: '#f8fafc',
    fontSize: 18,
    fontWeight: '800',
  },
  appSubtitle: {
    color: '#94a3b8',
    fontSize: 12,
    marginTop: 2,
  },
  tabBar: {
    flexDirection: 'row',
    paddingHorizontal: 18,
    paddingVertical: 10,
    gap: 10,
    backgroundColor: '#0f172a',
  },
  tabButton: {
    flex: 1,
    paddingVertical: 10,
    borderRadius: 10,
    backgroundColor: '#1e293b',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#334155',
  },
  tabButtonActive: {
    backgroundColor: '#1d4ed8',
    borderColor: '#3b82f6',
  },
  tabText: {
    color: '#94a3b8',
    fontSize: 13,
    fontWeight: '700',
  },
  tabTextActive: {
    color: '#ffffff',
  },
  content: {
    flex: 1,
  },
});

