// @ts-check
import { Router } from 'express';
import { authenticateUser, requireRole } from '../middlewares/auth.middleware.js';
import { getDatabase } from '../db/database.js';
import { getSecurityAuditLogs, logSecurityEvent, AuditEventType } from '../services/audit.service.js';

const router = Router();

// Proteger todas las rutas de administración con autenticación y verificación de rol 'ADMIN' (RF-03, RF-07)
router.use(authenticateUser);
router.use(requireRole(['ADMIN']));

/**
 * RF-07: Listar todos los usuarios registrados (exclusivo para administradores)
 */
router.get('/users', async (req, res, next) => {
  try {
    const db = getDatabase();
    const users = await db.prepare(`
      SELECT id, email, role, created_at, updated_at
      FROM users
      ORDER BY created_at DESC
    `).all();

    await logSecurityEvent({
      eventType: AuditEventType.ADMIN_USER_LIST_ACCESSED,
      userId: req.user.id,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.json({ users });
  } catch (error) {
    next(error);
  }
});

/**
 * RF-07: Consultar bitácora de auditoría y eventos de seguridad
 */
router.get('/audit-logs', async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
    const offset = Math.max(Number(req.query.offset) || 0, 0);

    const logs = await getSecurityAuditLogs(limit, offset);

    await logSecurityEvent({
      eventType: AuditEventType.ADMIN_AUDIT_LOGS_ACCESSED,
      userId: req.user.id,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      details: { limit, offset },
    });

    res.json({
      logs,
      pagination: { limit, offset, count: logs.length },
    });
  } catch (error) {
    next(error);
  }
});

export default router;
