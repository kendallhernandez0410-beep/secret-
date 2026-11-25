// @ts-check
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { getDatabase } from '../db/database.js';
import { env } from '../config/env.js';
import {
  generatePasswordResetToken,
  hashTokenSHA256,
  timingSafeStringCompare,
} from '../crypto/vault.crypto.js';
import { logSecurityEvent, AuditEventType } from './audit.service.js';

// Costo mínimo mandatorio para bcrypt (>= 12)
const BCRYPT_SALT_ROUNDS = 12;

// Política de contraseñas de alta seguridad (RF-01 / NIST SP 800-63B)
export const passwordPolicySchema = z
  .string()
  .min(12, { message: 'La contraseña debe tener al menos 12 caracteres.' })
  .max(128, { message: 'La contraseña no puede exceder 128 caracteres.' })
  .regex(/[A-Z]/, { message: 'La contraseña debe contener al menos una letra mayúscula.' })
  .regex(/[a-z]/, { message: 'La contraseña debe contener al menos una letra minúscula.' })
  .regex(/[0-9]/, { message: 'La contraseña debe contener al menos un dígito numérico.' })
  .regex(/[^A-Za-z0-9]/, { message: 'La contraseña debe contener al menos un carácter especial (@$!%*?&#...etc).' });

export const registerSchema = z.object({
  email: z.string().email({ message: 'Dirección de correo electrónico inválida.' }).toLowerCase().trim(),
  password: passwordPolicySchema,
  // Nota: Prohibido aceptar 'role' del cliente en registro (prevención de elevación de privilegios OWASP A01)
});

export const loginSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
  password: z.string().min(1),
});

export const forgotPasswordSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
});

export const resetPasswordSchema = z.object({
  token: z.string().length(64, { message: 'El token de recuperación debe ser un hash de 64 caracteres hex.' }),
  newPassword: passwordPolicySchema,
});

/**
 * Registra un nuevo usuario aplicando política de contraseña y forzando rol 'USER'.
 * 
 * @param {object} input
 * @param {string} input.email
 * @param {string} input.password
 * @param {string} [ipAddress]
 * @param {string} [userAgent]
 * @returns {Promise<{ id: string, email: string, role: string, createdAt: string }>}
 */
export async function registerUser({ email, password }, ipAddress = 'unknown', userAgent = 'unknown') {
  const db = getDatabase();

  // Comprobar existencia previa de email
  const existing = await db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    const error = new Error('El correo electrónico ya está registrado.');
    // @ts-ignore
    error.statusCode = 409;
    throw error;
  }

  // Hash robusto con bcrypt (factor de costo 12)
  const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

  const id = crypto.randomUUID();
  const role = 'USER'; // Rol inmutable en autoregistro
  const now = new Date().toISOString();

  const insertStmt = db.prepare(`
    INSERT INTO users (id, email, password_hash, role, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  await insertStmt.run(id, email, passwordHash, role, now, now);

  logSecurityEvent({
    eventType: AuditEventType.AUTH_REGISTER_SUCCESS,
    userId: id,
    ipAddress,
    userAgent,
    details: { email },
  });

  return { id, email, role, createdAt: now };
}

/**
 * Autentica credenciales y emite token JWT con claims firmados.
 * 
 * @param {object} input
 * @param {string} input.email
 * @param {string} input.password
 * @param {string} [ipAddress]
 * @param {string} [userAgent]
 * @returns {Promise<{ token: string, user: { id: string, email: string, role: string } }>}
 */
export async function loginUser({ email, password }, ipAddress = 'unknown', userAgent = 'unknown') {
  const db = getDatabase();

  const user = await db.prepare('SELECT id, email, password_hash, role FROM users WHERE email = ?').get(email);

  // Anti-timing leak: si el usuario no existe, ejecutamos un compare falso con hash ficticio
  if (!user) {
    await bcrypt.compare(password, '$2a$12$e8YkY6e8G6v5mZ1o2p3q4e5r6t7y8u9i0o1p2a3s4d5f6g7h8j9k0');
    logSecurityEvent({
      eventType: AuditEventType.AUTH_LOGIN_FAILURE,
      ipAddress,
      userAgent,
      details: { email, reason: 'USER_NOT_FOUND' },
    });
    const error = new Error('Credenciales inválidas.');
    // @ts-ignore
    error.statusCode = 401;
    throw error;
  }

  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) {
    logSecurityEvent({
      eventType: AuditEventType.AUTH_LOGIN_FAILURE,
      userId: user.id,
      ipAddress,
      userAgent,
      details: { email, reason: 'INVALID_PASSWORD' },
    });
    const error = new Error('Credenciales inválidas.');
    // @ts-ignore
    error.statusCode = 401;
    throw error;
  }

  // Generación de JWT firmado con HMAC-SHA256 y expiración corta (15 min)
  const tokenPayload = {
    sub: user.id,
    email: user.email,
    role: user.role,
  };

  const token = jwt.sign(tokenPayload, env.JWT_SECRET, {
    expiresIn: '15m',
    algorithm: 'HS256',
  });

  logSecurityEvent({
    eventType: AuditEventType.AUTH_LOGIN_SUCCESS,
    userId: user.id,
    ipAddress,
    userAgent,
    details: { role: user.role },
  });

  return {
    token,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
    },
  };
}

/**
 * Solicita restablecimiento de contraseña generando un token seguro de un solo uso (RF-06).
 * Siempre responde éxito para evitar enumeración de cuentas de usuario (OWASP A07).
 * 
 * @param {string} email
 * @param {string} [ipAddress]
 * @param {string} [userAgent]
 * @returns {Promise<{ message: string, debugToken?: string }>}
 */
export async function requestPasswordReset(email, ipAddress = 'unknown', userAgent = 'unknown') {
  const db = getDatabase();
  const user = await db.prepare('SELECT id FROM users WHERE email = ?').get(email);

  let rawTokenForDebug = undefined;

  if (user) {
    const { rawToken, tokenHash } = generatePasswordResetToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minutos de vigencia
    const now = new Date().toISOString();

    // Invalidar tokens previos pendientes
    await db.prepare('UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0').run(user.id);

    // Insertar nuevo registro con hash SHA-256
    await db.prepare(`
      INSERT INTO password_resets (id, user_id, token_hash, expires_at, used, created_at)
      VALUES (?, ?, ?, ?, 0, ?)
    `).run(crypto.randomUUID(), user.id, tokenHash, expiresAt, now);

    logSecurityEvent({
      eventType: AuditEventType.AUTH_FORGOT_PASSWORD_REQUEST,
      userId: user.id,
      ipAddress,
      userAgent,
      details: { email },
    });

    // En entorno de laboratorio/test podemos retornar el debugToken para automatización de pruebas
    if (env.NODE_ENV !== 'production') {
      rawTokenForDebug = rawToken;
    }
  } else {
    logSecurityEvent({
      eventType: AuditEventType.AUTH_FORGOT_PASSWORD_REQUEST,
      ipAddress,
      userAgent,
      details: { email, note: 'NON_EXISTENT_EMAIL' },
    });
  }

  // Respuesta uniforme anti-enumeración
  return {
    message: 'Si el correo electrónico existe en nuestra base de datos, se ha enviado un enlace seguro para restablecer la contraseña.',
    debugToken: rawTokenForDebug,
  };
}

/**
 * Restablece la contraseña validando el hash SHA-256 del token y su vigencia (RF-06).
 * El token es de un solo uso y se invalida de forma inmediata.
 * 
 * @param {object} input
 * @param {string} input.token
 * @param {string} input.newPassword
 * @param {string} [ipAddress]
 * @param {string} [userAgent]
 * @returns {Promise<{ success: boolean, message: string }>}
 */
export async function resetPassword({ token, newPassword }, ipAddress = 'unknown', userAgent = 'unknown') {
  const db = getDatabase();

  const candidateHash = hashTokenSHA256(token);

  // Búsqueda del token por su hash
  const record = await db.prepare(`
    SELECT id, user_id, token_hash, expires_at, used
    FROM password_resets
    WHERE token_hash = ?
  `).get(candidateHash);

  if (!record) {
    logSecurityEvent({
      eventType: AuditEventType.AUTH_RESET_PASSWORD_FAILURE,
      ipAddress,
      userAgent,
      details: { reason: 'TOKEN_NOT_FOUND' },
    });
    const error = new Error('Token de recuperación inválido o expirado.');
    // @ts-ignore
    error.statusCode = 400;
    throw error;
  }

  // Validación de uso previo
  if (record.used === 1) {
    logSecurityEvent({
      eventType: AuditEventType.AUTH_RESET_PASSWORD_FAILURE,
      userId: record.user_id,
      ipAddress,
      userAgent,
      details: { reason: 'TOKEN_ALREADY_USED' },
    });
    const error = new Error('El token ya ha sido utilizado.');
    // @ts-ignore
    error.statusCode = 400;
    throw error;
  }

  // Validación de expiración
  const now = new Date();
  const expiresAt = new Date(record.expires_at);
  if (now > expiresAt) {
    logSecurityEvent({
      eventType: AuditEventType.AUTH_RESET_PASSWORD_FAILURE,
      userId: record.user_id,
      ipAddress,
      userAgent,
      details: { reason: 'TOKEN_EXPIRED' },
    });
    const error = new Error('El token de recuperación ha expirado.');
    // @ts-ignore
    error.statusCode = 400;
    throw error;
  }

  // Verificación en tiempo constante contra manipulación
  const isValid = timingSafeStringCompare(candidateHash, record.token_hash);
  if (!isValid) {
    const error = new Error('Token inválido.');
    // @ts-ignore
    error.statusCode = 400;
    throw error;
  }

  // Hashear nueva contraseña
  const newPasswordHash = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);
  const updatedAt = new Date().toISOString();

  await db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?')
    .run(newPasswordHash, updatedAt, record.user_id);

  await db.prepare('UPDATE password_resets SET used = 1 WHERE id = ?')
    .run(record.id);

  logSecurityEvent({
    eventType: AuditEventType.AUTH_RESET_PASSWORD_SUCCESS,
    userId: record.user_id,
    ipAddress,
    userAgent,
    details: { message: 'PASSWORD_RESET_SUCCESSFUL' },
  });

  return {
    success: true,
    message: 'Contraseña actualizada exitosamente. Ya puede iniciar sesión con sus nuevas credenciales.',
  };
}
