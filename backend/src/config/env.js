// @ts-check
import dotenv from 'dotenv';
import { z } from 'zod';
import crypto from 'node:crypto';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().min(0).max(65535).default(3000),
  HOST: z.string().default('127.0.0.1'),
  ENCRYPTION_MASTER_KEY: z.string().refine((val) => {
    try {
      const buf = Buffer.from(val, 'hex');
      return buf.length === 32;
    } catch {
      return false;
    }
  }, {
    message: 'ENCRYPTION_MASTER_KEY debe ser un string hexadecimal de exactamente 64 caracteres (32 bytes / 256 bits).',
  }),
  JWT_SECRET: z.string().min(32, {
    message: 'JWT_SECRET debe tener al menos 32 caracteres (256 bits) para garantizar resistencia criptográfica.',
  }),
  DATABASE_PATH: z.string().default('./data/securevault.db'),
  TRUST_PROXY: z.string().transform((v) => v === 'true' || v === '1').default('false'),
  ALLOWED_ORIGIN: z.string().default('http://localhost:3000'),

  // Configuración de MySQL
  DB_CLIENT: z.enum(['mysql', 'sqlite']).default('mysql'),
  DB_HOST: z.string().default('127.0.0.1'),
  DB_PORT: z.coerce.number().int().default(3306),
  DB_USER: z.string().default('root'),
  DB_PASSWORD: z.string().default('1234'),
  DB_NAME: z.string().default('securevault_db'),
});

// En entornos de testing permitimos llaves autogeneradas seguras si no existen
if (process.env.NODE_ENV === 'test') {
  if (!process.env.ENCRYPTION_MASTER_KEY) {
    process.env.ENCRYPTION_MASTER_KEY = crypto.randomBytes(32).toString('hex');
  }
  if (!process.env.JWT_SECRET) {
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
  }
}

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌ Error fatal de configuración de entorno (Security Misconfiguration):');
  console.error(parsed.error.format());
  process.exit(1);
}

export const env = parsed.data;
