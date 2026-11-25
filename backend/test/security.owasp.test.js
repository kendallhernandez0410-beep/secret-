// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { getDatabase } from '../src/db/database.js';

let server;
let baseUrl = '';
let db;

test.before(async () => {
  db = getDatabase(':memory:');
  const app = createApp();

  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve(null);
    });
  });
});

test.after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('OWASP A03:2025 - Resistencia absoluta a SQL Injection (Prepared Statements)', async () => {
  const sqlPayloads = [
    "' OR '1'='1",
    "admin' --",
    "'; DROP TABLE users; --",
    "' UNION SELECT null, null, null, null, null, null --",
    "\" OR \"\"=\"",
  ];

  for (const payload of sqlPayloads) {
    const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: payload,
        password: 'Password123!@#',
      }),
    });

    // Debe ser rechazado como credenciales inválidas (401) o email malformado (400), NUNCA 500 ni bypass
    assert.ok(
      [400, 401].includes(res.status),
      `Payload SQLi ${payload} no debe provocar error 500 ni permitir bypass. Status recibido: ${res.status}`
    );
  }

  // Comprobar que la tabla users sigue existiendo y sin alteraciones
  const tableCheck = await db.prepare("SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='users'").get();
  assert.equal(tableCheck.count, 1, 'La tabla users no debe ser alterada');
});

test('OWASP A05:2025 - Cabeceras de Seguridad y Protección contra Clickjacking / MIME Sniffing', async () => {
  const res = await fetch(`${baseUrl}/health`);

  // Cabeceras mandatorias de hardening
  assert.equal(res.headers.get('x-frame-options'), 'DENY', 'Debe denegar el framing para mitigar clickjacking');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff', 'Debe evitar sniffing de MIME types');
  assert.ok(res.headers.get('content-security-policy'), 'Debe incluir Content-Security-Policy');
  assert.equal(res.headers.get('x-powered-by'), null, 'X-Powered-By no debe existir');
});

test('OWASP A07:2025 - Mitigación de Fuerza Bruta mediante Rate Limiting en /auth/*', async () => {
  let rateLimited = false;

  // Realizar múltiples llamadas consecutivas rápidas para agotar la cuota de la ventana
  for (let i = 0; i < 25; i++) {
    const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `attacker${i}@test.com`,
        password: 'Password123!@#',
      }),
    });

    if (res.status === 429) {
      rateLimited = true;
      const body = await res.json();
      assert.match(body.error, /Demasiadas solicitudes/, 'Debe retornar mensaje de rate limit');
      break;
    }
  }

  assert.equal(rateLimited, true, 'El limitador de tasa debe bloquear ráfagas de autenticación (HTTP 429)');
});

test('OWASP A09:2025 - Sanitización de PII y Secreción en Bitácoras', async () => {
  // Simular evento con payload sensible intentando filtrarse a los logs
  const { logSecurityEvent, AuditEventType, getSecurityAuditLogs } = await import('../src/services/audit.service.js');

  await logSecurityEvent({
    eventType: AuditEventType.AUTH_LOGIN_FAILURE,
    ipAddress: '192.168.1.100',
    userAgent: 'SecurityScanner/1.0',
    details: {
      email: 'victim@vault.com',
      password: 'SuperSecretPasswordDontLogMe123!',
      rawToken: 'd4f8e6c4b2a1...',
      cookie: 'secret_session_data',
    },
  });

  const logs = await getSecurityAuditLogs(10, 0);
  const failureLog = logs.find((l) => l.event_type === AuditEventType.AUTH_LOGIN_FAILURE && l.ip_address === '192.168.1.100');
  
  assert.ok(failureLog, 'El evento debe estar registrado');
  assert.doesNotMatch(failureLog.details, /SuperSecretPasswordDontLogMe123!/, 'La contraseña no debe aparecer en los logs');
  assert.doesNotMatch(failureLog.details, /d4f8e6c4b2a1/, 'El token en crudo no debe aparecer en los logs');
  assert.match(failureLog.details, /\[REDACTED_BY_AUDIT_POLICY\]/, 'Los campos sensibles deben ser redactados');
});
