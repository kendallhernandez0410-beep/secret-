// @ts-check
import crypto from 'node:crypto';
import { z } from 'zod';
import { getDatabase } from '../db/database.js';
import {
  encryptAES256GCM,
  decryptAES256GCM,
  maskSensitiveData,
} from '../crypto/vault.crypto.js';
import { logSecurityEvent, AuditEventType } from './audit.service.js';

export const createNoteSchema = z.object({
  title: z.string().min(1, 'El título es obligatorio.').max(200, 'El título no puede exceder 200 caracteres.').trim(),
  content: z.string().min(1, 'El contenido es obligatorio.').max(10000, 'El contenido no puede exceder 10,000 caracteres.'),
  sensitiveField: z.string().min(1, 'El campo sensible es obligatorio.').max(500, 'El campo sensible no puede exceder 500 caracteres.'),
});

export const updateNoteSchema = createNoteSchema.partial();

/**
 * Servicio de Notas Privadas Cifradas con Mitigación Estricta de IDOR / BOLA (RF-04, RF-05)
 */

/**
 * Crea una nueva nota con contenido cifrado en AES-256-GCM y campo sensible enmascarado.
 * 
 * @param {object} input
 * @param {string} input.userId
 * @param {string} input.title
 * @param {string} input.content
 * @param {string} input.sensitiveField
 * @param {string} [ipAddress]
 * @param {string} [userAgent]
 * @returns {Promise<{ id: string, title: string, sensitiveFieldMasked: string, createdAt: string }>}
 */
export async function createNote({ userId, title, content, sensitiveField }, ipAddress = 'unknown', userAgent = 'unknown') {
  const db = getDatabase();
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  // Empaquetar y cifrar contenido privado junto al campo sensible con AES-256-GCM
  const payloadToEncrypt = JSON.stringify({
    content,
    sensitiveField,
  });

  const { encryptedString } = encryptAES256GCM(payloadToEncrypt);
  const sensitiveFieldMasked = maskSensitiveData(sensitiveField);

  const stmt = db.prepare(`
    INSERT INTO notes (id, user_id, title, encrypted_content, sensitive_field_masked, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  await stmt.run(id, userId, title, encryptedString, sensitiveFieldMasked, now, now);

  await logSecurityEvent({
    eventType: AuditEventType.NOTE_CREATED,
    userId,
    ipAddress,
    userAgent,
    details: { noteId: id, title },
  });

  return {
    id,
    title,
    sensitiveFieldMasked,
    createdAt: now,
  };
}

/**
 * Lista las notas del usuario autenticado. Cada usuario SOLO ve sus propios registros.
 * 
 * @param {string} userId
 * @returns {Promise<Array<{ id: string, title: string, sensitiveFieldMasked: string, createdAt: string, updatedAt: string }>>}
 */
export async function listUserNotes(userId) {
  const db = getDatabase();

  // Consulta parametrizada estrictamente ligada al userId autenticado (Anti-IDOR)
  const stmt = db.prepare(`
    SELECT id, title, sensitive_field_masked, created_at, updated_at
    FROM notes
    WHERE user_id = ?
    ORDER BY created_at DESC
  `);

  const rows = await stmt.all(userId);

  return rows.map((r) => ({
    id: r.id,
    title: r.title,
    sensitiveFieldMasked: r.sensitive_field_masked,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
}

/**
 * Obtiene y descifra una nota asegurando que pertenezca al usuario autenticado (Anti-IDOR / RF-04).
 * Si un usuario intenta acceder a una nota de otro usuario, se registra una alerta de seguridad.
 * 
 * @param {string} noteId
 * @param {string} userId
 * @param {boolean} [isAdmin=false]
 * @param {string} [ipAddress]
 * @param {string} [userAgent]
 * @returns {Promise<{ id: string, title: string, content: string, sensitiveField: string, sensitiveFieldMasked: string, createdAt: string, updatedAt: string }>}
 */
export async function getNoteById(noteId, userId, isAdmin = false, ipAddress = 'unknown', userAgent = 'unknown') {
  const db = getDatabase();

  let note = null;

  if (isAdmin) {
    // Si es administrador, puede consultar cualquier nota para propósitos de auditoría supervisada
    note = await db.prepare('SELECT * FROM notes WHERE id = ?').get(noteId);
  } else {
    // Para usuarios estándar: scoped query obligatoria por userId
    note = await db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?').get(noteId, userId);
  }

  if (!note) {
    // Verificar si la nota existe pero pertenece a otro usuario para detectar intento deliberado de IDOR
    const existsOtherUser = await db.prepare('SELECT user_id FROM notes WHERE id = ?').get(noteId);

    if (existsOtherUser && existsOtherUser.user_id !== userId) {
      await logSecurityEvent({
        eventType: AuditEventType.ACCESS_DENIED_IDOR,
        userId,
        ipAddress,
        userAgent,
        details: { targetNoteId: noteId, victimUserId: existsOtherUser.user_id },
      });
    }

    const error = new Error('Nota no encontrada o acceso no autorizado.');
    // @ts-ignore
    error.statusCode = 404; // Respuesta 404 opaca para evitar divulgación de existencia
    throw error;
  }

  // Descifrado con AES-256-GCM y verificación de integridad
  const decryptedRaw = decryptAES256GCM(note.encrypted_content);
  const parsedPayload = JSON.parse(decryptedRaw);

  await logSecurityEvent({
    eventType: AuditEventType.NOTE_READ,
    userId,
    ipAddress,
    userAgent,
    details: { noteId },
  });

  return {
    id: note.id,
    title: note.title,
    content: parsedPayload.content,
    sensitiveField: parsedPayload.sensitiveField,
    sensitiveFieldMasked: note.sensitive_field_masked,
    createdAt: note.created_at,
    updatedAt: note.updated_at,
  };
}

/**
 * Actualiza una nota con nuevo cifrado y verificación estricta de tenencia.
 * 
 * @param {object} input
 * @param {string} input.noteId
 * @param {string} input.userId
 * @param {string} [input.title]
 * @param {string} [input.content]
 * @param {string} [input.sensitiveField]
 * @param {string} [ipAddress]
 * @param {string} [userAgent]
 */
export async function updateNote({ noteId, userId, title, content, sensitiveField }, ipAddress = 'unknown', userAgent = 'unknown') {
  const db = getDatabase();

  // 1. Obtener nota existente del usuario
  const existing = await db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?').get(noteId, userId);
  if (!existing) {
    const error = new Error('Nota no encontrada o acceso no autorizado.');
    // @ts-ignore
    error.statusCode = 404;
    throw error;
  }

  // 2. Descifrar contenido previo si alguno de los campos sensibles no se actualiza
  const currentDecrypted = JSON.parse(decryptAES256GCM(existing.encrypted_content));

  const updatedTitle = title !== undefined ? title : existing.title;
  const updatedContent = content !== undefined ? content : currentDecrypted.content;
  const updatedSensitive = sensitiveField !== undefined ? sensitiveField : currentDecrypted.sensitiveField;

  // 3. Re-cifrar con un nuevo IV fresco
  const { encryptedString } = encryptAES256GCM(JSON.stringify({
    content: updatedContent,
    sensitiveField: updatedSensitive,
  }));

  const updatedMasked = maskSensitiveData(updatedSensitive);
  const now = new Date().toISOString();

  const updateStmt = db.prepare(`
    UPDATE notes
    SET title = ?, encrypted_content = ?, sensitive_field_masked = ?, updated_at = ?
    WHERE id = ? AND user_id = ?
  `);

  await updateStmt.run(updatedTitle, encryptedString, updatedMasked, now, noteId, userId);

  await logSecurityEvent({
    eventType: AuditEventType.NOTE_UPDATED,
    userId,
    ipAddress,
    userAgent,
    details: { noteId },
  });

  return {
    id: noteId,
    title: updatedTitle,
    sensitiveFieldMasked: updatedMasked,
    updatedAt: now,
  };
}

/**
 * Elimina una nota asegurando que pertenezca al usuario autenticado (Anti-IDOR).
 * 
 * @param {string} noteId
 * @param {string} userId
 * @param {string} [ipAddress]
 * @param {string} [userAgent]
 */
export async function deleteNote(noteId, userId, ipAddress = 'unknown', userAgent = 'unknown') {
  const db = getDatabase();

  const stmt = db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
  const result = await stmt.run(noteId, userId);

  if (result.changes === 0) {
    const error = new Error('Nota no encontrada o acceso no autorizado.');
    // @ts-ignore
    error.statusCode = 404;
    throw error;
  }

  await logSecurityEvent({
    eventType: AuditEventType.NOTE_DELETED,
    userId,
    ipAddress,
    userAgent,
    details: { noteId },
  });

  return { success: true, message: 'Nota eliminada exitosamente.' };
}
