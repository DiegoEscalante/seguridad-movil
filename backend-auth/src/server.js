const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { verifyTOTPWithWindow, computeCodeChallenge, generateTOTP } = require('./totp');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'unisabana-compass-secret-key-2026';

// Semilla TOTP oficial de la guía para paridad con Google Authenticator
const DEFAULT_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
const DEFAULT_USER = {
  id: 'usr_unisabana_01',
  email: 'estudiante@unisabana.edu.co',
  name: 'Estudiante Ingeniería',
  totpSecret: DEFAULT_TOTP_SECRET,
};

// Almacenamiento en memoria
const authCodes = new Map();     // code -> { codeChallenge, codeChallengeMethod, redirectUri, userId, expiresAt }
const authorizedByState = new Map(); // state -> { code, state, redirectUrl, expiresAt } (Respaldo para Expo Go / Custom Tabs)
const refreshTokens = new Map(); // refreshToken -> { userId, expiresAt }
const stepUpTokens = new Map();  // stepUpToken -> { userId, expiresAt }
const replayCache = new Map();   // `${userId}:${code}` -> expiresAt (TTL 90s)

// Limpieza periódica de caché Anti-Replay
setInterval(() => {
  const now = Date.now();
  for (const [key, exp] of replayCache.entries()) {
    if (exp <= now) replayCache.delete(key);
  }
}, 15000);

function issueAccessToken(user, mfaVerified = false, expiresIn = '5m') {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      name: user.name,
      mfa_verified: mfaVerified,
    },
    JWT_SECRET,
    { expiresIn }
  );
}

// Middleware de autenticación Bearer
function authenticateBearer(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', message: 'Token Bearer faltante' });
  }
  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'token_expired_or_invalid', message: 'El access_token expiró o es inválido' });
  }
}

// ============================================================================
// FASE 1: OAuth 2.0 con PKCE (RFC 7636)
// ============================================================================

/**
 * GET /oauth/authorize
 * Renderiza la página de proveedor de identidad en el navegador seguro del sistema.
 */
app.get('/oauth/authorize', (req, res) => {
  const {
    response_type = 'code',
    client_id = 'unisabana-mobile',
    redirect_uri = 'unisabana-auth://callback',
    code_challenge,
    code_challenge_method = 'S256',
    state,
  } = req.query;

  if (!code_challenge || !state) {
    return res.status(400).send('Faltan parámetros requeridos de PKCE (code_challenge o state).');
  }

  const html = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>UniSabana Identity Provider - OAuth 2.0 + PKCE</title>
  <style>
    * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { margin: 0; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 16px; max-width: 400px; width: 100%; padding: 28px 24px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
    .badge { display: inline-block; background: #1d4ed8; color: #dbeafe; font-size: 12px; font-weight: 600; padding: 4px 10px; border-radius: 999px; margin-bottom: 12px; }
    h1 { font-size: 20px; margin: 0 0 8px; }
    p { font-size: 14px; color: #94a3b8; margin: 0 0 20px; line-height: 1.5; }
    .meta { background: #0f172a; border-radius: 10px; padding: 12px; font-family: monospace; font-size: 11px; color: #cbd5e1; margin-bottom: 20px; word-break: break-all; }
    .meta div { margin-bottom: 6px; }
    .meta span { color: #38bdf8; }
    label { display: block; font-size: 13px; color: #cbd5e1; margin-bottom: 6px; font-weight: 500; }
    input { width: 100%; padding: 11px 12px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #fff; font-size: 14px; margin-bottom: 16px; }
    button { width: 100%; padding: 13px; border-radius: 10px; border: none; background: #2563eb; color: white; font-weight: 600; font-size: 15px; cursor: pointer; }
    button:active { background: #1d4ed8; }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">OAuth 2.0 + PKCE (RFC 7636)</span>
    <h1>UniSabana SSO</h1>
    <p>Autoriza a <strong>${client_id}</strong> para iniciar sesión de forma segura mediante navegador del sistema.</p>
    <div class="meta">
      <div><span>Challenge (S256):</span> ${code_challenge}</div>
      <div><span>State Anti-CSRF:</span> ${state}</div>
    </div>
    <form method="POST" action="/oauth/authorize/decision">
      <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
      <input type="hidden" name="code_challenge" value="${code_challenge}" />
      <input type="hidden" name="code_challenge_method" value="${code_challenge_method}" />
      <input type="hidden" name="state" value="${state}" />
      <label>Correo institucional</label>
      <input type="email" name="email" value="estudiante@unisabana.edu.co" readonly />
      <label>Contraseña (Demo)</label>
      <input type="password" name="password" value="••••••••••••" readonly />
      <button type="submit">Autorizar y Volver a la App</button>
    </form>
  </div>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

/**
 * POST /oauth/authorize/decision
 * Genera el authorization_code y redirige al Deep Link de la app móvil.
 * Nota: En Android Chrome Custom Tabs, un HTTP 302 directo a partir de un POST hacia un custom
 * scheme (exp:// o unisabana-auth://) es bloqueado por Chromium ("Found. Redirecting to...").
 * Devolver una página HTML con window.location.replace() + enlace de respaldo dispara el Intent nativo.
 */
app.post('/oauth/authorize/decision', (req, res) => {
  const { redirect_uri, code_challenge, code_challenge_method = 'S256', state } = req.body;

  const code = 'auth_' + crypto.randomBytes(18).toString('hex');
  authCodes.set(code, {
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    redirectUri: redirect_uri,
    userId: DEFAULT_USER.id,
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 min
  });

  const separator = redirect_uri.includes('?') ? '&' : '?';
  const targetUrl = `${redirect_uri}${separator}code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`;

  authorizedByState.set(state, {
    code,
    state,
    redirectUrl: targetUrl,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  // Devolvemos una confirmación limpia mientras la app en segundo plano detecta la autorización
  // en <500ms y ejecuta WebBrowser.dismissAuthSession() sin reiniciar Expo Go.
  const doneHtml = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Autorización Completada</title>
  <style>
    body { margin: 0; background: #0f172a; color: #f8fafc; font-family: -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; text-align: center; }
    .box { background: #1e293b; border: 1px solid #10b981; border-radius: 16px; padding: 28px 24px; max-width: 380px; width: 100%; }
    .icon { font-size: 40px; margin-bottom: 12px; }
    h2 { margin: 0 0 10px; font-size: 19px; color: #34d399; }
    p { color: #cbd5e1; font-size: 14px; margin: 0; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="box">
    <div class="icon">✅</div>
    <h2>¡Identidad Verificada!</h2>
    <p>Código OAuth 2.0 + PKCE emitido.<br/>Volviendo a la aplicación automáticamente...</p>
  </div>
  <script>
    try { window.close(); } catch (e) {}
  </script>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(doneHtml);
});

/**
 * GET /oauth/poll/:state
 * Permite a la app en Expo Go detectar instantáneamente cuando el usuario presionó "Autorizar"
 * en Chrome Custom Tabs y cerrar la pestaña automáticamente si el navegador retiene el Deep Link.
 */
app.get('/oauth/poll/:state', (req, res) => {
  const record = authorizedByState.get(req.params.state);
  if (!record || record.expiresAt < Date.now()) {
    return res.json({ authorized: false });
  }
  return res.json({
    authorized: true,
    code: record.code,
    state: record.state,
    redirectUrl: record.redirectUrl,
  });
});

/**
 * POST /auth/oauth/token
 * Intercambia authorization_code + code_verifier por access_token y refresh_token.
 */
app.post('/auth/oauth/token', (req, res) => {
  const { code, code_verifier } = req.body;

  if (!code || !code_verifier) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Se requieren code y code_verifier',
    });
  }

  const record = authCodes.get(code);
  if (!record || record.expiresAt < Date.now()) {
    authCodes.delete(code);
    return res.status(400).json({
      error: 'invalid_grant',
      message: 'El código de autorización es inválido o ha expirado',
    });
  }

  // Consumir código de un solo uso
  authCodes.delete(code);

  // Validar PKCE: SHA256(code_verifier) === code_challenge
  const computedChallenge = computeCodeChallenge(code_verifier);
  if (computedChallenge !== record.codeChallenge) {
    return res.status(400).json({
      error: 'invalid_grant',
      message: 'Fallo en verificación PKCE: SHA256(code_verifier) no coincide con code_challenge',
    });
  }

  const accessToken = issueAccessToken(DEFAULT_USER, false, '5m');
  const refreshToken = 'rt_' + crypto.randomBytes(32).toString('hex');

  // Persistir refresh_token (vida útil 30 días)
  refreshTokens.set(refreshToken, {
    userId: DEFAULT_USER.id,
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
  });

  return res.json({
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: 'Bearer',
    expires_in: 300,
    user: {
      id: DEFAULT_USER.id,
      email: DEFAULT_USER.email,
      name: DEFAULT_USER.name,
    },
  });
});

// ============================================================================
// PUNTO 2: Renovación Silenciosa (Silent Refresh)
// ============================================================================

/**
 * POST /auth/refresh
 * Recibe el refresh_token almacenado en Keychain/Keystore y emite un nuevo access_token.
 */
app.post('/auth/refresh', (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(401).json({ error: 'invalid_refresh_token', message: 'refresh_token requerido' });
  }

  const record = refreshTokens.get(refresh_token);
  if (!record || record.expiresAt < Date.now()) {
    refreshTokens.delete(refresh_token);
    return res.status(401).json({ error: 'refresh_token_expired', message: 'El refresh_token expiró o fue revocado' });
  }

  const newAccessToken = issueAccessToken(DEFAULT_USER, false, '5m');
  return res.json({
    access_token: newAccessToken,
    token_type: 'Bearer',
    expires_in: 300,
  });
});

/**
 * GET /api/perfil
 * Endpoint autenticado estándar para demostrar el interceptor 401 y Silent Refresh Queue.
 */
app.get('/api/perfil', authenticateBearer, (req, res) => {
  return res.json({
    user: {
      id: req.user.sub,
      email: req.user.email,
      name: req.user.name,
      mfa_verified: Boolean(req.user.mfa_verified),
    },
    serverTime: new Date().toISOString(),
  });
});

// ============================================================================
// PUNTO 4: Step-Up Authentication & Anti-Replay
// ============================================================================

/**
 * Handler compartido para GET /api/boveda y GET /api/boveda-critica
 */
function handleBovedaCritica(req, res) {
  if (!req.user.mfa_verified) {
    const stepUpToken = 'stup_' + crypto.randomBytes(20).toString('hex');
    stepUpTokens.set(stepUpToken, {
      userId: req.user.sub,
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutos para completar el desafío
    });

    return res.status(403).json({
      error: 'mfa_required',
      message: 'Este recurso crítico requiere verificación de segundo factor (Step-Up 2FA TOTP).',
      step_up_token: stepUpToken,
    });
  }

  return res.json({
    status: 'unlocked',
    title: 'Bóveda Crítica UniSabana',
    mfa_verified: true,
    secrets: [
      { id: 'key-1', label: 'Llave Maestra HSM Producción', value: 'USAB-HSM-9941-X82B-77A0' },
      { id: 'key-2', label: 'Certificado Raíz Firma Digital', value: 'SHA256:8f4e2b91c04d...e91a' },
      { id: 'key-3', label: 'Token Auditoría Financiera', value: 'FIN-2026-PRIVATE-VAULT' },
    ],
    accessedAt: new Date().toISOString(),
  });
}

app.get('/api/boveda', authenticateBearer, handleBovedaCritica);
app.get('/api/boveda-critica', authenticateBearer, handleBovedaCritica);

/**
 * POST /auth/mfa/verify
 * Valida step_up_token + código TOTP de 6 dígitos en ventanas (C-1, C, C+1) y caché Anti-Replay (TTL 90s).
 */
app.post('/auth/mfa/verify', (req, res) => {
  const { step_up_token, code } = req.body;

  if (!step_up_token || !code) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Se requieren step_up_token y el código TOTP de 6 dígitos.',
    });
  }

  const stepUpRecord = stepUpTokens.get(step_up_token);
  if (!stepUpRecord || stepUpRecord.expiresAt < Date.now()) {
    return res.status(401).json({
      error: 'invalid_step_up_token',
      message: 'El step_up_token es inválido o ha expirado. Solicita acceso al recurso nuevamente.',
    });
  }

  const sanitizedCode = String(code).trim();
  const replayKey = `${stepUpRecord.userId}:${sanitizedCode}`;

  // 1. Verificar Caché Anti-Replay antes o durante la ventana de validez
  const replayExpiresAt = replayCache.get(replayKey);
  if (replayExpiresAt && replayExpiresAt > Date.now()) {
    return res.status(409).json({
      error: 'replay_detected',
      message: 'Replay Attack Detected: Este código TOTP ya fue utilizado dentro de la ventana de validez.',
    });
  }

  // 2. Validar código en ventanas C-1 (t-30s), C (t), C+1 (t+30s)
  const verification = verifyTOTPWithWindow(DEFAULT_USER.totpSecret, sanitizedCode);
  if (!verification.valid) {
    return res.status(401).json({
      error: 'invalid_totp_code',
      message: 'Código TOTP inválido o fuera de ventana temporal (C-1, C, C+1).',
    });
  }

  // 3. Registrar código en caché Anti-Replay con TTL de 90 segundos
  replayCache.set(replayKey, Date.now() + 90 * 1000);

  // 4. Emitir elevated_token con mfa_verified: true (expiración corta: 10 minutos)
  const elevatedToken = issueAccessToken(DEFAULT_USER, true, '10m');

  return res.json({
    elevated_token: elevatedToken,
    mfa_verified: true,
    expires_in: 600,
    matched_window_step: verification.matchedStep,
  });
});

/**
 * Endpoint auxiliar para verificar estado del servidor
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    otpauth_uri: `otpauth://totp/UniSabana:${DEFAULT_USER.email}?secret=${DEFAULT_TOTP_SECRET}&issuer=UniSabana`,
    current_server_totp_demo: generateTOTP(DEFAULT_TOTP_SECRET),
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`========================================================`);
  console.log(`Backend de Seguridad Móvil ejecutándose en puerto ${PORT}`);
  console.log(`Semilla TOTP Base32: ${DEFAULT_TOTP_SECRET}`);
  console.log(`URI QR: otpauth://totp/UniSabana:${DEFAULT_USER.email}?secret=${DEFAULT_TOTP_SECRET}&issuer=UniSabana`);
  console.log(`========================================================`);
});

