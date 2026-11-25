// @ts-check
import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { getDatabase } from '../src/db/database.js';

let server;
let baseUrl = '';
let db;

test.before(async () => {
  // Inicializar base de datos en memoria para aislamiento absoluto en pruebas
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

test('RF-08 & OWASP A05 - GET /health sin fingerprinting ni headers de stack', async () => {
  const res = await fetch(`${baseUrl}/health`);
  assert.equal(res.status, 200);

  const body = await res.json();
  assert.equal(body.status, 'UP');
  assert.ok(body.timestamp);
  assert.equal(body.version, undefined, 'No debe revelar versión de software');
  assert.equal(body.nodeVersion, undefined, 'No debe revelar versión de Node');

  // Comprobar ausencia estricta de X-Powered-By
  assert.equal(res.headers.get('x-powered-by'), null, 'X-Powered-By debe estar completamente suprimido');
  // Comprobar cabeceras Helmet
  assert.ok(res.headers.get('x-frame-options'), 'Debe incluir X-Frame-Options');
  assert.ok(res.headers.get('x-content-type-options'), 'Debe incluir X-Content-Type-Options: nosniff');
});

test('RF-01 - Registro con validación estricta de política de contraseñas', async () => {
  // 1. Contraseña débil (< 12 caracteres)
  const weakRes1 = await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'user1@example.com', password: 'Pass1!' }),
  });
  assert.equal(weakRes1.status, 400);

  // 2. Contraseña débil (sin números ni caracteres especiales)
  const weakRes2 = await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'user1@example.com', password: 'PasswordSinEspeciales' }),
  });
  assert.equal(weakRes2.status, 400);

  // 3. Contraseña válida y robusta (>= 12 caracteres, mayúscula, minúscula, dígito, símbolo)
  const strongRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'user1@example.com',
      password: 'Master#Vault$2026!Sec',
      role: 'ADMIN', // Intento de inyección de rol para verificar mitigación A01
    }),
  });
  assert.equal(strongRes.status, 201);
  const data = await strongRes.json();
  assert.equal(data.user.email, 'user1@example.com');
  assert.equal(data.user.role, 'USER', 'El rol DEBE ser USER a pesar del payload inyectado');
});

let user1Token = '';
let user2Token = '';
let user1Id = '';
let user2Id = '';
let adminToken = '';

test('RF-02 - Login seguro y emisión de Cookie / Token JWT', async () => {
  // Login exitoso Usuario 1
  const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'user1@example.com',
      password: 'Master#Vault$2026!Sec',
    }),
  });

  assert.equal(loginRes.status, 200);
  const loginData = await loginRes.json();
  assert.ok(loginData.token);
  user1Token = loginData.token;
  user1Id = loginData.user.id;

  // Registrar y loguear Usuario 2 (para pruebas de IDOR)
  await fetch(`${baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'user2@example.com',
      password: 'User2#Vault$2026!Sec',
    }),
  });

  const loginRes2 = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'user2@example.com',
      password: 'User2#Vault$2026!Sec',
    }),
  });
  const loginData2 = await loginRes2.json();
  user2Token = loginData2.token;
  user2Id = loginData2.user.id;

  // Crear y loguear cuenta de Administrador directamente en BD
  const adminId = 'admin-uuid-001';
  await db.prepare(`
    INSERT INTO users (id, email, password_hash, role, created_at, updated_at)
    VALUES (?, ?, ?, 'ADMIN', datetime('now'), datetime('now'))
  `).run(adminId, 'admin@securevault.local', '$2a$12$e8YkY6e8G6v5mZ1o2p3q4e5r6t7y8u9i0o1p2a3s4d5f6g7h8j9k0');

  // Login del admin (simulado con JWT directo firmado)
  const jwt = (await import('jsonwebtoken')).default;
  const { env } = await import('../src/config/env.js');
  adminToken = jwt.sign(
    { sub: adminId, email: 'admin@securevault.local', role: 'ADMIN' },
    env.JWT_SECRET,
    { expiresIn: '15m' }
  );
});

test('RF-03 - Control de Acceso Basado en Roles (RBAC) verificado en servidor', async () => {
  // Usuario normal intenta acceder al panel de usuarios admin
  const userAccess = await fetch(`${baseUrl}/api/v1/admin/users`, {
    headers: { Authorization: `Bearer ${user1Token}` },
  });
  assert.equal(userAccess.status, 403, 'Usuario normal debe recibir 403 Forbidden en admin');

  // Administrador accede al panel
  const adminAccess = await fetch(`${baseUrl}/api/v1/admin/users`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert.equal(adminAccess.status, 200, 'Administrador debe recibir 200 OK');
  const adminData = await adminAccess.json();
  assert.ok(Array.isArray(adminData.users));
  assert.ok(adminData.users.length >= 2);
});

let noteIdUser1 = '';

test('RF-04 & RF-05 - CRUD de notas privadas cifradas y enmascaramiento de campo sensible', async () => {
  // 1. Crear nota privada cifrada con AES-256-GCM
  const createRes = await fetch(`${baseUrl}/api/v1/notes`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${user1Token}`,
    },
    body: JSON.stringify({
      title: 'Credencial Servidor Producción',
      content: 'Host: 10.0.0.1 - Usuario: root - Key: SSH_RSA_SUPER_SECRET',
      sensitiveField: '4111-2222-3333-4444',
    }),
  });

  assert.equal(createRes.status, 201);
  const createData = await createRes.json();
  assert.ok(createData.note.id);
  noteIdUser1 = createData.note.id;
  assert.equal(createData.note.sensitiveFieldMasked, '********-4444', 'El campo sensible debe estar enmascarado');

  // 2. Listar notas: el listado muestra el resumen enmascarado y no expone el contenido en claro
  const listRes = await fetch(`${baseUrl}/api/v1/notes`, {
    headers: { Authorization: `Bearer ${user1Token}` },
  });
  assert.equal(listRes.status, 200);
  const listData = await listRes.json();
  assert.equal(listData.notes.length, 1);
  assert.equal(listData.notes[0].sensitiveFieldMasked, '********-4444');
  assert.equal(listData.notes[0].content, undefined, 'El listado no debe exponer contenido en claro');

  // 3. Obtener nota por ID (Descifrado legítimo por su propietario)
  const getRes = await fetch(`${baseUrl}/api/v1/notes/${noteIdUser1}`, {
    headers: { Authorization: `Bearer ${user1Token}` },
  });
  assert.equal(getRes.status, 200);
  const getData = await getRes.json();
  assert.equal(getData.note.content, 'Host: 10.0.0.1 - Usuario: root - Key: SSH_RSA_SUPER_SECRET');
  assert.equal(getData.note.sensitiveField, '4111-2222-3333-4444');
});

test('RF-04 & OWASP A01 - Mitigación estricta de IDOR (BOLA)', async () => {
  // Usuario 2 intenta LEER la nota de Usuario 1
  const idorReadRes = await fetch(`${baseUrl}/api/v1/notes/${noteIdUser1}`, {
    headers: { Authorization: `Bearer ${user2Token}` },
  });
  assert.equal(idorReadRes.status, 404, 'Debe denegar lectura IDOR con respuesta opaca 404');

  // Usuario 2 intenta MODIFICAR la nota de Usuario 1
  const idorUpdateRes = await fetch(`${baseUrl}/api/v1/notes/${noteIdUser1}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${user2Token}`,
    },
    body: JSON.stringify({ title: 'Título hackeado' }),
  });
  assert.equal(idorUpdateRes.status, 404, 'Debe denegar actualización IDOR');

  // Usuario 2 intenta ELIMINAR la nota de Usuario 1
  const idorDeleteRes = await fetch(`${baseUrl}/api/v1/notes/${noteIdUser1}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${user2Token}` },
  });
  assert.equal(idorDeleteRes.status, 404, 'Debe denegar eliminación IDOR');

  // Confirmar que la nota de Usuario 1 sigue intacta
  const verifyRes = await fetch(`${baseUrl}/api/v1/notes/${noteIdUser1}`, {
    headers: { Authorization: `Bearer ${user1Token}` },
  });
  assert.equal(verifyRes.status, 200);
  const verifyData = await verifyRes.json();
  assert.equal(verifyData.note.title, 'Credencial Servidor Producción');
});

test('RF-06 - Recuperación de contraseña segura con token de 1 solo uso (SHA-256)', async () => {
  // 1. Solicitar reseteo de contraseña
  const forgotRes = await fetch(`${baseUrl}/api/v1/auth/forgot-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'user1@example.com' }),
  });

  assert.equal(forgotRes.status, 200);
  const forgotData = await forgotRes.json();
  const rawToken = forgotData.debugToken;
  assert.ok(rawToken, 'En test mode se provee el debugToken generado por crypto.randomBytes(32)');

  // 2. Ejecutar reseteo con el token legítimo
  const resetRes = await fetch(`${baseUrl}/api/v1/auth/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: rawToken,
      newPassword: 'BrandNew#Password2026!',
    }),
  });

  assert.equal(resetRes.status, 200);

  // 3. Intentar REUTILIZAR el mismo token (Prevención de re-uso / Single-use enforcement)
  const reuseRes = await fetch(`${baseUrl}/api/v1/auth/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: rawToken,
      newPassword: 'Another#Password2026!',
    }),
  });
  assert.equal(reuseRes.status, 400, 'El token no debe poder ser reutilizado');

  // 4. Iniciar sesión con la contraseña anterior (Debe fallar)
  const oldLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'user1@example.com',
      password: 'Master#Vault$2026!Sec',
    }),
  });
  assert.equal(oldLoginRes.status, 401, 'La contraseña antigua debe estar invalidada');

  // 5. Iniciar sesión con la nueva contraseña (Debe ser exitoso)
  const newLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'user1@example.com',
      password: 'BrandNew#Password2026!',
    }),
  });
  assert.equal(newLoginRes.status, 200);
});

test('RF-07 & OWASP A09 - Bitácora de auditoría inmutable y sanitizada', async () => {
  const auditRes = await fetch(`${baseUrl}/api/v1/admin/audit-logs`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });

  assert.equal(auditRes.status, 200);
  const auditData = await auditRes.json();
  assert.ok(auditData.logs.length > 0);

  // Comprobar que los logs registraron eventos críticos
  const eventTypes = auditData.logs.map((l) => l.event_type);
  assert.ok(eventTypes.includes('AUTH_REGISTER_SUCCESS'));
  assert.ok(eventTypes.includes('AUTH_LOGIN_SUCCESS'));
  assert.ok(eventTypes.includes('ACCESS_DENIED_IDOR'), 'El intento de IDOR debe quedar registrado en auditoría');
  assert.ok(eventTypes.includes('AUTH_RESET_PASSWORD_SUCCESS'));

  // Comprobar que NINGÚN log contiene contraseñas ni tokens en texto claro
  for (const log of auditData.logs) {
    if (log.details) {
      assert.doesNotMatch(log.details, /Master#Vault/, 'Prohibido registrar passwords en logs');
      assert.doesNotMatch(log.details, /BrandNew#Password/, 'Prohibido registrar passwords en logs');
    }
  }
});
