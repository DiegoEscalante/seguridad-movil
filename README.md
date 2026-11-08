# Laboratorio Seguridad Móvil — OAuth 2.0 con PKCE, Almacenamiento Criptográfico y Step-Up 2FA (TOTP)

**Universidad de La Sabana — Facultad de Ingeniería**  
**Curso:** Desarrollo Móvil (React Native con Expo) · **Sesión 14**

---

## Estructura del Proyecto

```text
.
├── backend-auth/                 # Servidor ligero en Node.js + Express
│   ├── package.json
│   └── src/
│       ├── server.js             # Endpoints OAuth 2.0 + PKCE, Silent Refresh, Step-Up y Anti-Replay
│       └── totp.js               # Algoritmo RFC 6238 (HMAC-SHA1 + Dynamic Truncation) y ventanas C-1, C, C+1
├── mobile-app/                   # Aplicación React Native (Expo + TypeScript)
│   ├── App.tsx                   # Navegación limpia entre Login/Bóveda y Módulo Authenticator Offline
│   ├── app.json                  # Configuración de Deep Link scheme: "unisabana-auth" y permisos
│   ├── package.json
│   └── src/
│       ├── api/
│       │   └── apiClient.ts      # Axios Interceptor con Silent Refresh Queue (pausa y encola en 401)
│       ├── context/
│       │   └── AuthContext.tsx   # Estado volátil de access_token en RAM + flujo WebBrowser PKCE
│       ├── crypto/
│       │   ├── pkce.ts           # Generador criptográfico code_verifier, code_challenge (S256) y state
│       │   └── totp.ts           # Implementación desde cero de TOTP (RFC 6238) + parser Base32 / otpauth://
│       ├── screens/
│       │   ├── AuthenticatorScreen.tsx # Generador TOTP de 6 dígitos con barra de 30s, QR y Modo Avión
│       │   ├── LoginScreen.tsx         # Inicio de sesión con navegador seguro del sistema
│       │   └── VaultScreen.tsx         # Bóveda Crítica, modal Step-Up 2FA y pruebas de Anti-Replay / 401
│       └── storage/
│           └── secureStorage.ts  # Persistencia en hardware Keychain / Keystore vía expo-secure-store
└── README.md
```

---

## Requisitos e Instalación Paso a Paso

### 1. Ejecutar el Backend (`/backend-auth`)

```bash
cd backend-auth
npm install
npm start
```

El servidor quedará escuchando en `http://0.0.0.0:3000`:
- **Semilla Base32 por defecto:** `JBSWY3DPEHPK3PXP`
- **URI QR compatible con Google Authenticator:**
  `otpauth://totp/UniSabana:estudiante@unisabana.edu.co?secret=JBSWY3DPEHPK3PXP&issuer=UniSabana`

### 2. Ejecutar la App Móvil (`/mobile-app`)

```bash
cd mobile-app
npm install
npx expo start
```

> **Nota sobre la dirección IP en dispositivos físicos / emuladores:**
> En la pantalla de inicio de sesión de la app puedes ajustar la URL del backend directamente:
> - **Emulador Android:** `http://10.0.2.2:3000`
> - **Simulador iOS:** `http://localhost:3000`
> - **Teléfono Físico (Expo Go):** `http://<IP_LOCAL_DE_TU_PC>:3000`

---

## Guía para las 5 Pruebas de Sustentación en Vivo

1. **Flujo OAuth + PKCE con Navegador del Sistema:**
   - En la pestaña **1. Login OAuth + PKCE**, presiona **"Iniciar Sesión con Navegador Seguro"**.
   - Se abrirá `WebBrowser.openAuthSessionAsync` (sin usar `WebView`), mostrando el challenge SHA-256 y el `state` anti-CSRF.
   - Al autorizar, regresa mediante Deep Link, valida `state`, intercambia `code + code_verifier` en `POST /auth/oauth/token`, guarda `access_token` únicamente en memoria RAM y cifra `refresh_token` en `expo-secure-store`.
2. **Paridad Estándar TOTP:**
   - Abre la pestaña **2. Authenticator TOTP**. La semilla `JBSWY3DPEHPK3PXP` (o escaneada por QR) mostrará exactamente los mismos 6 dígitos que Google Authenticator en tiempo real.
3. **Cálculo Offline en Modo Avión:**
   - Activa el **Modo Avión** en el teléfono y observa cómo el temporizador de 30s llega a `0s` y calcula matemáticamente el nuevo código de 6 dígitos sin realizar peticiones de red.
4. **Step-Up Authentication & Bóveda Crítica:**
   - Con sesión iniciada, presiona **"Abrir Bóveda Crítica"**. La API responderá `403 Forbidden (mfa_required)` con un `step_up_token` y se abrirá automáticamente el modal 2FA para ingresar el código TOTP y obtener el `elevated_token` (`mfa_verified: true`).
5. **Ataque de Repetición (Anti-Replay) y Silent Refresh Queue:**
   - Presiona **"Probar Ataque Replay (409)"** inmediatamente después de desbloquear la bóveda: el backend rechazará el código repetido con `409 Conflict: Replay Attack Detected`.
   - Presiona **"Probar Cola 401 Refresh"** para invalidar el `access_token` en RAM y disparar 3 peticiones simultáneas que se pausan y resuelven con un único `POST /auth/refresh`.

