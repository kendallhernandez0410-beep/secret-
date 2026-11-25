// @ts-check
import { createApp } from './app.js';
import { env } from './config/env.js';
import { getDatabase } from './db/database.js';

const app = createApp();

// Inicializar base de datos
getDatabase();

const server = app.listen(env.PORT, env.HOST, () => {
  console.log(`🛡️  SecureVault iniciado de forma segura en http://${env.HOST}:${env.PORT}`);
  console.log(`🔒 Entorno: ${env.NODE_ENV}`);
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
