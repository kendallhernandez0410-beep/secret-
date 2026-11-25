// @ts-check
import crypto from 'node:crypto';

/**
 * Módulo Criptográfico de Alto Nivel para SecureVault
 * Basado estrictamente en NIST SP 800-38D (AES-GCM), RFC 9106 y NIST SP 800-63B.
 * 
 * Reglas mandatorias aplicadas:
 * - AES-256-GCM para confidencialidad e integridad (AEAD)
 * - IV aleatorio de 12 bytes (96 bits) por cada registro cifrado (CSPRNG)
 * - AuthTag de 16 bytes (128 bits)
 * - SHA-256 para almacenamiento de tokens de restablecimiento de contraseña
 * - crypto.timingSafeEqual para prevención de ataques de temporización (timing attacks)
 * - Prohibido: AES-ECB, createCipher desactualizado, Math.random(), reutilización de IVs.
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12; // 96 bits recomendado por NIST para GCM
const AUTH_TAG_LENGTH_BYTES = 16; // 128 bits para máxima seguridad de autenticación

/**
 * Valida y obtiene la llave maestra de 256 bits (32 bytes).
 * @param {string} [keyHex]
 * @returns {Buffer}
 */
export function getValidatedMasterKey(keyHex = process.env.ENCRYPTION_MASTER_KEY) {
  if (!keyHex) {
    throw new Error('FATAL: ENCRYPTION_MASTER_KEY no está definida en las variables de entorno.');
  }

  const keyBuffer = Buffer.from(keyHex, 'hex');
  if (keyBuffer.length !== 32) {
    throw new Error(`FATAL: ENCRYPTION_MASTER_KEY debe ser de 32 bytes (256 bits). Longitud actual: ${keyBuffer.length} bytes.`);
  }

  return keyBuffer;
}

/**
 * Cifra un texto utilizando AES-256-GCM con un IV único generado con CSPRNG.
 * 
 * @param {string} plaintext - Texto en claro a cifrar.
 * @param {Buffer} [masterKey] - Llave de 32 bytes (opcional, por defecto toma la del entorno).
 * @returns {{ encryptedString: string, ivHex: string, tagHex: string, cipherHex: string }}
 */
export function encryptAES256GCM(plaintext, masterKey = getValidatedMasterKey()) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('El texto a cifrar debe ser una cadena (string).');
  }

  // Generación de IV fresco e irrepetible para cada cifrado (CSPRNG)
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);

  // Instanciación del cifrador AEAD
  const cipher = crypto.createCipheriv(ALGORITHM, masterKey, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });

  const encryptedBuffer = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  const ivHex = iv.toString('hex');
  const tagHex = authTag.toString('hex');
  const cipherHex = encryptedBuffer.toString('hex');

  // Formato serializado seguro: iv:tag:ciphertext
  const encryptedString = `${ivHex}:${tagHex}:${cipherHex}`;

  return {
    encryptedString,
    ivHex,
    tagHex,
    cipherHex,
  };
}

/**
 * Descifra una cadena cifrada en formato 'iv:tag:ciphertext' mediante AES-256-GCM.
 * Si el tag o el ciphertext han sido manipulados, la operación falla catastróficamente.
 * 
 * @param {string} encryptedPayload - Cadena serializada en formato 'iv:tag:ciphertext'.
 * @param {Buffer} [masterKey] - Llave de 32 bytes.
 * @returns {string} - Texto en claro original.
 */
export function decryptAES256GCM(encryptedPayload, masterKey = getValidatedMasterKey()) {
  if (typeof encryptedPayload !== 'string') {
    throw new TypeError('El payload cifrado debe ser una cadena (string).');
  }

  const parts = encryptedPayload.split(':');
  if (parts.length !== 3) {
    throw new Error('Formato de payload cifrado inválido. Se esperaba "iv:tag:ciphertext".');
  }

  const [ivHex, tagHex, cipherHex] = parts;
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(tagHex, 'hex');
  const encryptedBuffer = Buffer.from(cipherHex, 'hex');

  if (iv.length !== IV_LENGTH_BYTES) {
    throw new Error(`IV inválido. Longitud esperada: ${IV_LENGTH_BYTES} bytes, recibida: ${iv.length}.`);
  }

  if (authTag.length !== AUTH_TAG_LENGTH_BYTES) {
    throw new Error(`AuthTag inválido. Longitud esperada: ${AUTH_TAG_LENGTH_BYTES} bytes, recibida: ${authTag.length}.`);
  }

  const decipher = crypto.createDecipheriv(ALGORITHM, masterKey, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });

  // Establecer el tag de autenticación antes de final()
  decipher.setAuthTag(authTag);

  try {
    const decryptedBuffer = Buffer.concat([
      decipher.update(encryptedBuffer),
      decipher.final(),
    ]);

    return decryptedBuffer.toString('utf8');
  } catch (error) {
    // Falla de integridad o manipulación deliberada (OWASP A02 / A08)
    throw new Error('Fallo de integridad criptográfica: datos manipulados o clave incorrecta.');
  }
}

/**
 * Genera un token criptográficamente seguro de 256 bits (32 bytes) para recuperación de contraseña.
 * Retorna el token en claro (para enviar al usuario) y su hash SHA-256 (para almacenar en base de datos).
 * 
 * @returns {{ rawToken: string, tokenHash: string }}
 */
export function generatePasswordResetToken() {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashTokenSHA256(rawToken);
  return { rawToken, tokenHash };
}

/**
 * Calcula el digest SHA-256 de un token en formato hexadecimal.
 * @param {string} token
 * @returns {string}
 */
export function hashTokenSHA256(token) {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Compara dos cadenas de longitud fija en tiempo constante para mitigar ataques de temporización.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function timingSafeStringCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) {
    // Simular comparación constante para no fugar información por longitud inmediata
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Enmascara un campo de datos sensible para despliegue en listados o logs (RF-05).
 * - Números o cadenas tipo tarjeta/cuenta: oculta todo excepto los últimos 4 caracteres.
 * - Cadenas genéricas cortas: muestra primer y último caracter con máscara intermedia.
 * 
 * @param {string} sensitiveText
 * @returns {string}
 */
export function maskSensitiveData(sensitiveText) {
  if (!sensitiveText || typeof sensitiveText !== 'string') {
    return '****';
  }

  const trimmed = sensitiveText.trim();
  if (trimmed.length <= 4) {
    return '****';
  }

  if (trimmed.length <= 8) {
    return `${trimmed.slice(0, 1)}${'*'.repeat(trimmed.length - 2)}${trimmed.slice(-1)}`;
  }

  // Para cadenas más largas (>= 9 caracteres): máscara conservando últimos 4 caracteres
  const maskedLength = trimmed.length - 4;
  return `${'*'.repeat(Math.min(maskedLength, 8))}-${trimmed.slice(-4)}`;
}
