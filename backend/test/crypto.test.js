import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  getValidatedMasterKey,
  encryptAES256GCM,
  decryptAES256GCM,
  generatePasswordResetToken,
  hashTokenSHA256,
  timingSafeStringCompare,
  maskSensitiveData,
} from '../src/crypto/vault.crypto.js';

const TEST_MASTER_KEY = crypto.randomBytes(32);
const TEST_MASTER_KEY_HEX = TEST_MASTER_KEY.toString('hex');

test('Criptografía - Validación de llave maestra de 256 bits (32 bytes)', () => {
  const key = getValidatedMasterKey(TEST_MASTER_KEY_HEX);
  assert.equal(key.length, 32);

  // Llave de longitud incorrecta debe fallar
  assert.throws(() => {
    getValidatedMasterKey('aabbcc');
  }, /ENCRYPTION_MASTER_KEY debe ser de 32 bytes/);

  // Llave ausente debe fallar
  assert.throws(() => {
    getValidatedMasterKey('');
  }, /ENCRYPTION_MASTER_KEY no está definida/);
});

test('Criptografía - AES-256-GCM Cifrado y Descifrado exitoso', () => {
  const secretData = 'Confidential Bank Account: 9876-5432-1098-7654 | API_KEY: secret_live_xyz';
  
  const { encryptedString, ivHex, tagHex, cipherHex } = encryptAES256GCM(secretData, TEST_MASTER_KEY);

  // Verificación de longitudes y formato
  assert.equal(Buffer.from(ivHex, 'hex').length, 12, 'El IV debe ser de 12 bytes (96 bits)');
  assert.equal(Buffer.from(tagHex, 'hex').length, 16, 'El AuthTag debe ser de 16 bytes (128 bits)');
  assert.match(encryptedString, /^[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]+$/);

  // Descifrado
  const decrypted = decryptAES256GCM(encryptedString, TEST_MASTER_KEY);
  assert.equal(decrypted, secretData, 'El texto descifrado debe coincidir exactamente con el original');
});

test('Criptografía - AES-256-GCM Detección de Manipulación (Integridad / AuthTag)', () => {
  const secretData = 'Monto a transferir: $500,000 USD';
  const { encryptedString } = encryptAES256GCM(secretData, TEST_MASTER_KEY);
  
  const [ivHex, tagHex, cipherHex] = encryptedString.split(':');

  // 1. Modificar un byte del ciphertext (Tampering)
  const tamperedCipher = (cipherHex.startsWith('00') ? 'ff' : '00') + cipherHex.slice(2);
  const tamperedPayload1 = `${ivHex}:${tagHex}:${tamperedCipher}`;
  assert.throws(() => {
    decryptAES256GCM(tamperedPayload1, TEST_MASTER_KEY);
  }, /Fallo de integridad criptográfica/, 'Debe fallar al alterar el ciphertext');

  // 2. Modificar un byte del AuthTag (Tampering)
  const tamperedTag = (tagHex.startsWith('00') ? 'ff' : '00') + tagHex.slice(2);
  const tamperedPayload2 = `${ivHex}:${tamperedTag}:${cipherHex}`;
  assert.throws(() => {
    decryptAES256GCM(tamperedPayload2, TEST_MASTER_KEY);
  }, /Fallo de integridad criptográfica/, 'Debe fallar al alterar el AuthTag');

  // 3. Modificar el IV
  const tamperedIV = (ivHex.startsWith('00') ? 'ff' : '00') + ivHex.slice(2);
  const tamperedPayload3 = `${tamperedIV}:${tagHex}:${cipherHex}`;
  assert.throws(() => {
    decryptAES256GCM(tamperedPayload3, TEST_MASTER_KEY);
  }, /Fallo de integridad criptográfica/, 'Debe fallar al alterar el IV');
});

test('Criptografía - Unicidad de IVs (Anti Reutilización de IV)', () => {
  const plaintext = 'Cadena idéntica repetida múltiples veces';
  const op1 = encryptAES256GCM(plaintext, TEST_MASTER_KEY);
  const op2 = encryptAES256GCM(plaintext, TEST_MASTER_KEY);

  assert.notEqual(op1.ivHex, op2.ivHex, 'Cada cifrado DEBE generar un IV diferente');
  assert.notEqual(op1.encryptedString, op2.encryptedString, 'Cifrados sucesivos del mismo texto deben diferir');
});

test('Criptografía - Tokens de recuperación SHA-256 de un solo uso', () => {
  const { rawToken, tokenHash } = generatePasswordResetToken();

  assert.equal(rawToken.length, 64, '32 bytes en hex = 64 caracteres de entropía CSPRNG');
  assert.equal(tokenHash.length, 64, 'SHA-256 en hex = 64 caracteres');

  // Verificación determinista del hash
  const expectedHash = hashTokenSHA256(rawToken);
  assert.equal(tokenHash, expectedHash);
  assert.notEqual(rawToken, tokenHash, 'El token en crudo y su hash no deben ser iguales');
});

test('Criptografía - Comparación en tiempo constante (timingSafeEqual)', () => {
  const hash1 = 'a'.repeat(64);
  const hash2 = 'a'.repeat(64);
  const hash3 = 'a'.repeat(63) + 'b';

  assert.equal(timingSafeStringCompare(hash1, hash2), true);
  assert.equal(timingSafeStringCompare(hash1, hash3), false);
  assert.equal(timingSafeStringCompare(hash1, 'corta'), false);
});

test('Criptografía - Enmascaramiento de datos sensibles (RF-05)', () => {
  assert.equal(maskSensitiveData('1234-5678-9012-3456'), '********-3456');
  assert.equal(maskSensitiveData('password_super_secreta'), '********-reta');
  assert.equal(maskSensitiveData('ABCDEFGH'), 'A******H');
  assert.equal(maskSensitiveData('1234'), '****');
  assert.equal(maskSensitiveData(''), '****');
});
