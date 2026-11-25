// @ts-check
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { env } from '../config/env.js';

let dbInstance = null;

/**
 * Inicializa y retorna la instancia de SQLite con esquema seguro y Foreign Keys habilitadas.
 * Utiliza consultas preparadas (Prepared Statements) de forma mandatoria.
 * 
 * @param {string} [customPath]
 * @returns {DatabaseSync}
 */
export function getDatabase(customPath) {
  if (dbInstance && !customPath) {
    return dbInstance;
  }

  const dbPath = customPath || env.DATABASE_PATH;

  if (dbPath !== ':memory:') {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const db = new DatabaseSync(dbPath);

  // Activación de restricciones de integridad referencial
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA journal_mode = WAL;'); // Write-Ahead Logging para rendimiento y resiliencia

  // Creación de tablas seguras
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'USER' CHECK (role IN ('USER', 'ADMIN')),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      encrypted_content TEXT NOT NULL,
      sensitive_field_masked TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS password_resets (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT UNIQUE NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1)),
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS security_audit_logs (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      user_id TEXT,
      ip_address TEXT NOT NULL,
      user_agent TEXT,
      details TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes (user_id);
    CREATE INDEX IF NOT EXISTS idx_password_resets_token_hash ON password_resets (token_hash);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON security_audit_logs (event_type);
  `);

  // Semilla de cuenta Administrador por defecto para pruebas si no existe
  if (dbPath !== ':memory:') {
    const adminExists = db.prepare("SELECT id FROM users WHERE email = 'admin@vault.local'").get();
    if (!adminExists) {
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO users (id, email, password_hash, role, created_at, updated_at)
        VALUES ('admin-default-id', 'admin@vault.local', '$2a$12$SoB1D0Zc7Z6cfThwLf70aOZKNbArH4/ksDcuJN1trqBjCcvDEz/zG', 'ADMIN', ?, ?)
      `).run(now, now);
    }
  }

  if (!customPath) {
    dbInstance = db;
  }

  return db;
}
