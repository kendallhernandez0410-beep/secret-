// @ts-check
import { DatabaseSync } from 'node:sqlite';
import mysql from 'mysql2/promise';
import fs from 'node:fs';
import path from 'node:path';
import { env } from '../config/env.js';

let dbInstance = null;
let mysqlPool = null;

const DEFAULT_ADMIN_HASH = '$2a$12$SoB1D0Zc7Z6cfThwLf70aOZKNbArH4/ksDcuJN1trqBjCcvDEz/zG'; // Admin#Vault2026!

/**
 * Inicializa la base de datos (MySQL o SQLite) creando el esquema relacional con Prepared Statements.
 */
export async function initDatabase() {
  if (env.DB_CLIENT === 'mysql') {
    // 1. Conexión inicial para asegurar que la base de datos exista
    const rootConn = await mysql.createConnection({
      host: env.DB_HOST,
      port: env.DB_PORT,
      user: env.DB_USER,
      password: env.DB_PASSWORD,
    });

    await rootConn.query(`CREATE DATABASE IF NOT EXISTS \`${env.DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`);
    await rootConn.end();

    // 2. Crear pool de conexiones permanente
    mysqlPool = mysql.createPool({
      host: env.DB_HOST,
      port: env.DB_PORT,
      user: env.DB_USER,
      password: env.DB_PASSWORD,
      database: env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });

    // 3. Crear tablas con restricciones de integridad referencial de forma individual
    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'USER',
        created_at VARCHAR(50) NOT NULL,
        updated_at VARCHAR(50) NOT NULL
      ) ENGINE=InnoDB;
    `);

    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS notes (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        title VARCHAR(255) NOT NULL,
        encrypted_content TEXT NOT NULL,
        sensitive_field_masked VARCHAR(255) NOT NULL,
        created_at VARCHAR(50) NOT NULL,
        updated_at VARCHAR(50) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      ) ENGINE=InnoDB;
    `);

    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        token_hash VARCHAR(64) UNIQUE NOT NULL,
        expires_at VARCHAR(50) NOT NULL,
        used TINYINT NOT NULL DEFAULT 0,
        created_at VARCHAR(50) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      ) ENGINE=InnoDB;
    `);

    await mysqlPool.query(`
      CREATE TABLE IF NOT EXISTS security_audit_logs (
        id VARCHAR(36) PRIMARY KEY,
        event_type VARCHAR(100) NOT NULL,
        user_id VARCHAR(36),
        ip_address VARCHAR(45) NOT NULL,
        user_agent VARCHAR(255),
        details TEXT,
        created_at VARCHAR(50) NOT NULL
      ) ENGINE=InnoDB;
    `);

    // 4. Semilla de Administrador por defecto
    const [adminCheck] = await mysqlPool.execute('SELECT id FROM users WHERE email = ?', ['admin@vault.local']);
    // @ts-ignore
    if (!adminCheck || adminCheck.length === 0) {
      const now = new Date().toISOString();
      await mysqlPool.execute(
        'INSERT INTO users (id, email, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
        ['admin-default-id', 'admin@vault.local', DEFAULT_ADMIN_HASH, 'ADMIN', now, now]
      );
    }

    dbInstance = {
      isMySQL: true,
      prepare: (sql) => ({
        get: async (...params) => {
          const [rows] = await mysqlPool.execute(sql, params);
          return rows && rows.length > 0 ? rows[0] : null;
        },
        all: async (...params) => {
          const [rows] = await mysqlPool.execute(sql, params);
          return rows || [];
        },
        run: async (...params) => {
          const [result] = await mysqlPool.execute(sql, params);
          return { changes: result.affectedRows, insertId: result.insertId };
        },
      }),
      exec: async (sql) => {
        await mysqlPool.query(sql);
      },
    };

    return dbInstance;
  }

  // Fallback SQLite (para pruebas unitarias y entornos sin servidor MySQL)
  return getSqliteDatabase();
}

function getSqliteDatabase(customPath) {
  const dbPath = customPath || env.DATABASE_PATH;

  if (dbPath !== ':memory:') {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const rawDb = new DatabaseSync(dbPath);
  rawDb.exec('PRAGMA foreign_keys = ON;');
  rawDb.exec('PRAGMA journal_mode = WAL;');

  rawDb.exec(`
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

  if (dbPath !== ':memory:') {
    const adminExists = rawDb.prepare("SELECT id FROM users WHERE email = 'admin@vault.local'").get();
    if (!adminExists) {
      const now = new Date().toISOString();
      rawDb.prepare(`
        INSERT INTO users (id, email, password_hash, role, created_at, updated_at)
        VALUES ('admin-default-id', 'admin@vault.local', '${DEFAULT_ADMIN_HASH}', 'ADMIN', ?, ?)
      `).run(now, now);
    }
  }

  // Envolver para exponer API asíncrona compatible
  const adapter = {
    isMySQL: false,
    prepare: (sql) => {
      const stmt = rawDb.prepare(sql);
      return {
        get: async (...params) => stmt.get(...params),
        all: async (...params) => stmt.all(...params),
        run: async (...params) => stmt.run(...params),
      };
    },
    exec: async (sql) => rawDb.exec(sql),
  };

  if (!customPath) {
    dbInstance = adapter;
  }

  return adapter;
}

/**
 * Retorna la instancia de base de datos activa.
 * @param {string} [customPath]
 */
export function getDatabase(customPath) {
  if (customPath || (!dbInstance && env.DB_CLIENT === 'sqlite')) {
    return getSqliteDatabase(customPath);
  }
  if (!dbInstance) {
    throw new Error('La base de datos aún no ha sido inicializada. Llame a initDatabase() primero.');
  }
  return dbInstance;
}
