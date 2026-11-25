// @ts-check
import crypto from 'node:crypto';
import { getDatabase } from '../db/database.js';

/**
 * Servicio de Auditoría y Trazabilidad de Seguridad (RF-07 / OWASP A09:2025)
 * Registra eventos sensibles con sanitización preventiva de secretos.
 */
export const AuditEventType = {
  AUTH_REGISTER_SUCCESS: 'AUTH_REGISTER_SUCCESS',
  AUTH_LOGIN_SUCCESS: 'AUTH_LOGIN_SUCCESS',
  AUTH_LOGIN_FAILURE: 'AUTH_LOGIN_FAILURE',
  AUTH_LOGOUT: 'AUTH_LOGOUT',
  AUTH_FORGOT_PASSWORD_REQUEST: 'AUTH_FORGOT_PASSWORD_REQUEST',
  AUTH_RESET_PASSWORD_SUCCESS: 'AUTH_RESET_PASSWORD_SUCCESS',
  AUTH_RESET_PASSWORD_FAILURE: 'AUTH_RESET_PASSWORD_FAILURE',
  NOTE_CREATED: 'NOTE_CREATED',
  NOTE_READ: 'NOTE_READ',
  NOTE_UPDATED: 'NOTE_UPDATED',
  NOTE_DELETED: 'NOTE_DELETED',
  ACCESS_DENIED_IDOR: 'ACCESS_DENIED_IDOR',
  ACCESS_DENIED_RBAC: 'ACCESS_DENIED_RBAC',
  ADMIN_USER_LIST_ACCESSED: 'ADMIN_USER_LIST_ACCESSED',
  ADMIN_AUDIT_LOGS_ACCESSED: 'ADMIN_AUDIT_LOGS_ACCESSED',
};

/**
 * Sanitiza cualquier objeto de detalles para impedir la fuga de contraseñas, tokens o PII en logs.
 * @param {Record<string, any>} [details]
 * @returns {string} JSON sanitizado
 */
function sanitizeDetails(details = {}) {
  const sensitiveKeys = ['password', 'rawToken', 'token', 'authorization', 'cookie', 'secret', 'encryptedContent'];
  const sanitized = { ...details };

  for (const key of Object.keys(sanitized)) {
    if (sensitiveKeys.some((s) => key.toLowerCase().includes(s.toLowerCase()))) {
      sanitized[key] = '[REDACTED_BY_AUDIT_POLICY]';
    }
  }

  return JSON.stringify(sanitized);
}

/**
 * Inserta un registro inmutable en la bitácora de auditoría.
 * 
 * @param {object} params
 * @param {string} params.eventType
 * @param {string} [params.userId]
 * @param {string} [params.ipAddress]
 * @param {string} [params.userAgent]
 * @param {Record<string, any>} [params.details]
 */
export async function logSecurityEvent({ eventType, userId = null, ipAddress = 'unknown', userAgent = 'unknown', details = {} }) {
  try {
    const db = getDatabase();
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    const sanitizedJson = sanitizeDetails(details);

    const stmt = db.prepare(`
      INSERT INTO security_audit_logs (id, event_type, user_id, ip_address, user_agent, details, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.run(id, eventType, userId, ipAddress, userAgent, sanitizedJson, createdAt);
  } catch (error) {
    // Si la auditoría falla, emitir advertencia a stderr sin detener la app (fail-safe logging)
    console.error('CRITICAL: Falla al registrar evento en bitácora de auditoría:', error.message);
  }
}

/**
 * Retorna la lista de eventos de auditoría para el panel de administración (RF-07).
 * @param {number} [limit=100]
 * @param {number} [offset=0]
 * @returns {Promise<Array<any>>}
 */
export async function getSecurityAuditLogs(limit = 100, offset = 0) {
  const db = getDatabase();
  const stmt = db.prepare(`
    SELECT id, event_type, user_id, ip_address, user_agent, details, created_at
    FROM security_audit_logs
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `);

  return await stmt.all(limit, offset);
}
