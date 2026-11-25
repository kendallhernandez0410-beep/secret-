// @ts-check
import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { env } from './config/env.js';
import { helmetConfig, generalRateLimiter, errorHandler } from './middlewares/security.middleware.js';

// Rutas
import authRouter from './routes/auth.routes.js';
import noteRouter from './routes/note.routes.js';
import adminRouter from './routes/admin.routes.js';
import healthRouter from './routes/health.routes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendPublicDir = path.resolve(__dirname, '../../frontend/public');

export function createApp() {
  const app = express();

  // 1. Hardening de Cabeceras y Fingerprinting
  app.disable('x-powered-by');
  app.use(helmetConfig);

  // 2. Configuración de Proxy Inverso (para HTTPS y Nginx/Caddy)
  if (env.TRUST_PROXY) {
    app.set('trust proxy', 1);
  }

  // 3. CORS restringido a orígenes autorizados
  app.use(cors({
    origin: env.ALLOWED_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));

  // 4. Rate-limiter general y Parsing de payloads con límite de tamaño (Anti-DoS)
  app.use(generalRateLimiter);
  app.use(express.json({ limit: '100kb' })); // Mitiga agotamiento de memoria por JSON bomb
  app.use(cookieParser());

  // 5. Servir el Frontend estático si existe
  if (fs.existsSync(frontendPublicDir)) {
    app.use(express.static(frontendPublicDir));
  }

  // 6. Montaje de Rutas API
  app.use('/health', healthRouter);
  app.use('/api/v1/auth', authRouter);
  app.use('/api/v1/notes', noteRouter);
  app.use('/api/v1/admin', adminRouter);

  // 7. Manejador de Recursos No Encontrados (404)
  app.use((req, res) => {
    res.status(404).json({
      error: 'Recurso no encontrado.',
      timestamp: new Date().toISOString(),
    });
  });

  // 8. Manejador Global de Errores
  app.use(errorHandler);

  return app;
}
