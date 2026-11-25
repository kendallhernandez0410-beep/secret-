// @ts-check
import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import { logSecurityEvent, AuditEventType } from '../services/audit.service.js';

/**
 * Middleware de Autenticación mediante JWT firmado criptográficamente.
 * Acepta tokens desde Cookies HttpOnly (preferido para navegadores) o cabecera Authorization (APIs).
 */
export function authenticateUser(req, res, next) {
  let token = null;

  // 1. Extraer desde Cookie HttpOnly segura
  if (req.cookies && req.cookies.securevault_session) {
    token = req.cookies.securevault_session;
  }
  // 2. O desde cabecera Authorization: Bearer <token>
  else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.substring(7);
  }

  if (!token) {
    return res.status(401).json({
      error: 'Acceso no autenticado. Se requiere un token de sesión válido.',
    });
  }

  try {
    const decoded = jwt.verify(token, env.JWT_SECRET, {
      algorithms: ['HS256'],
    });

    req.user = {
      id: decoded.sub,
      email: decoded.email,
      role: decoded.role,
    };

    next();
  } catch (error) {
    logSecurityEvent({
      eventType: AuditEventType.AUTH_LOGIN_FAILURE,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      details: { reason: 'INVALID_OR_EXPIRED_JWT', errorName: error.name },
    });

    return res.status(401).json({
      error: 'Sesión inválida o expirada. Por favor inicie sesión nuevamente.',
    });
  }
}

/**
 * Middleware de Autorización por Roles en Servidor (RBAC estricto - RF-03 / OWASP A01).
 * Nunca confía en información provista por el cliente; evalúa el rol verificado en el token.
 * 
 * @param {Array<string>} allowedRoles
 */
export function requireRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Usuario no autenticado.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      logSecurityEvent({
        eventType: AuditEventType.ACCESS_DENIED_RBAC,
        userId: req.user.id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: {
          userRole: req.user.role,
          requiredRoles: allowedRoles,
          path: req.originalUrl,
          method: req.method,
        },
      });

      return res.status(403).json({
        error: 'Acceso denegado: privilegios insuficientes para realizar esta operación.',
      });
    }

    next();
  };
}
