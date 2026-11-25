// @ts-check
import { Router } from 'express';

const router = Router();

/**
 * RF-08: Healthcheck Seguro sin Fingerprinting (OWASP A05: Security Misconfiguration)
 * 
 * Reglas mandatorias:
 * - Prohibido revelar versión de Node.js, Express o librerías internas.
 * - Prohibido exponer datos de memoria detallados, arquitectura de SO o stack traces.
 * - Cabecera X-Powered-By completamente deshabilitada.
 * - Payload estático mínimo.
 */
router.get('/', (req, res) => {
  res.status(200).json({
    status: 'UP',
    timestamp: new Date().toISOString(),
  });
});

export default router;
