// @ts-check
import { createApp } from './app.js';
import { env } from './config/env.js';
import { initDatabase } from './db/database.js';

// Inicializar base de datos (MySQL en dev/prod o SQLite)
await initDatabase();

const app = createApp();

const server = app.listen(env.PORT, env.HOST, () => {
  console.log(`🛡️  SecureVault iniciado de forma segura en http://${env.HOST}:${env.PORT}`);
  console.log(`🔒 Entorno: ${env.NODE_ENV}`);
  console.log(`🗄️  Motor de Base de Datos: ${env.DB_CLIENT.toUpperCase()} (${env.DB_CLIENT === 'mysql' ? env.DB_NAME : env.DATABASE_PATH})`);
  console.log(`✨ Estándar Criptográfico: AES-256-GCM + Bcrypt (Cost 12) + SHA-256`);
});

// Manejo de apagado elegante (Graceful Shutdown)
function handleShutdown(signal) {
  console.log(`\nRecibida señal ${signal}. Cerrando SecureVault de manera segura...`);
  server.close(() => {
    console.log('Conexiones HTTP cerradas. Servidor finalizado.');
    process.exit(0);
  });
}

process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));
