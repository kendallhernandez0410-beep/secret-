// @ts-check
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';

/**
 * Middleware para configurar cabeceras HTTP de seguridad robustas (OWASP A05: Security Misconfiguration)
 */
export const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000, // 1 año
    includeSubDomains: true,
    preload: true,
  },
  ieNoOpen: true,
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true,
});

/**
 * Limitador de tasa estricto para rutas de autenticación (RF-01, RF-02, RF-06 / OWASP A07)
 * Mitiga ataques de fuerza bruta y denegación de servicio en cálculos de hash.
 */
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // Ventana de 15 minutos
  max: 20, // Máximo 20 intentos por IP en 15 minutos
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Demasiadas solicitudes de autenticación desde esta dirección IP. Intente nuevamente en 15 minutos.',
  },
});

/**
 * Limitador general de tasa para la API
 */
export const generalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300, // 300 solicitudes por ventana de 15 minutos
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Límite de solicitudes de API excedido. Por favor reduzca la frecuencia de llamadas.',
  },
});

/**
 * Middleware de manejo global de excepciones y errores seguros.
 * Evita la divulgación de stack traces o rutas del sistema de archivos en producción (OWASP A05).
 */
export function errorHandler(err, req, res, next) {
  const statusCode = err.statusCode || (err.status && typeof err.status === 'number' ? err.status : 500);

  // En producción ocultamos detalles internos
  const message = statusCode === 500 && env.NODE_ENV === 'production'
    ? 'Ocurrió un error interno en el servidor.'
    : err.message || 'Error desconocido';

  const responseBody = {
    error: message,
    timestamp: new Date().toISOString(),
  };

  if (env.NODE_ENV !== 'production' && statusCode === 500) {
    responseBody.stack = err.stack;
  }

  res.status(statusCode).json(responseBody);
}
