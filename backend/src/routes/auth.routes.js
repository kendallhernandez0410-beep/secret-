// @ts-check
import { Router } from 'express';
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  registerUser,
  loginUser,
  requestPasswordReset,
  resetPassword,
} from '../services/auth.service.js';
import { authenticateUser } from '../middlewares/auth.middleware.js';
import { authRateLimiter } from '../middlewares/security.middleware.js';
import { logSecurityEvent, AuditEventType } from '../services/audit.service.js';
import { env } from '../config/env.js';

const router = Router();

// Aplicar rate-limiter estricto a todos los endpoints de autenticación
router.use(authRateLimiter);

/**
 * RF-01: Registro de usuario con validación estricta de política de contraseña
 */
router.post('/register', async (req, res, next) => {
  try {
    const validated = registerSchema.safeParse(req.body);
    if (!validated.success) {
      const issues = validated.error.issues || validated.error.errors || [];
      return res.status(400).json({
        error: 'Datos de registro inválidos.',
        details: issues.map((e) => e.message),
      });
    }

    const user = await registerUser(validated.data, req.ip, req.headers['user-agent']);
    res.status(201).json({
      message: 'Usuario registrado exitosamente.',
      user,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * RF-02: Inicio de sesión seguro con cookie HttpOnly y SameSite=Strict
 */
router.post('/login', async (req, res, next) => {
  try {
    const validated = loginSchema.safeParse(req.body);
    if (!validated.success) {
      return res.status(400).json({ error: 'Credenciales incompletas o inválidas.' });
    }

    const { token, user } = await loginUser(validated.data, req.ip, req.headers['user-agent']);

    // Configurar cookie segura
    const isProduction = env.NODE_ENV === 'production';
    res.cookie('securevault_session', token, {
      httpOnly: true,
      secure: isProduction, // HTTPS obligatorio en producción
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 minutos
      path: '/',
    });

    res.json({
      message: 'Inicio de sesión exitoso.',
      token, // También se entrega en payload para clientes sin soporte de cookies
      user,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * RF-02: Cierre de sesión seguro con invalidación de cookie
 */
router.post('/logout', authenticateUser, (req, res) => {
  res.clearCookie('securevault_session', {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
  });

  logSecurityEvent({
    eventType: AuditEventType.AUTH_LOGOUT,
    userId: req.user.id,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
  });

  res.json({ message: 'Sesión cerrada exitosamente.' });
});

/**
 * RF-06: Solicitud de restablecimiento de contraseña (Token CSPRNG + SHA-256)
 */
router.post('/forgot-password', async (req, res, next) => {
  try {
    const validated = forgotPasswordSchema.safeParse(req.body);
    if (!validated.success) {
      return res.status(400).json({ error: 'Debe ingresar un correo electrónico válido.' });
    }

    const result = await requestPasswordReset(validated.data.email, req.ip, req.headers['user-agent']);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

/**
 * RF-06: Consumo del token de restablecimiento de contraseña
 */
router.post('/reset-password', async (req, res, next) => {
  try {
    const validated = resetPasswordSchema.safeParse(req.body);
    if (!validated.success) {
      const issues = validated.error.issues || validated.error.errors || [];
      return res.status(400).json({
        error: 'Datos inválidos para restablecimiento.',
        details: issues.map((e) => e.message),
      });
    }

    const result = await resetPassword(validated.data, req.ip, req.headers['user-agent']);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

export default router;
