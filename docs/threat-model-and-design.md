# SecureVault — Documento de Arquitectura, Modelo de Amenazas y Especificación Criptográfica

**Versión:** 1.0.0  
**Fecha:** Noviembre 2026  
**Clasificación:** Confidencial / Proyecto de Aplicación Segura  
**Estándar de Referencia:** OWASP Top 10:2025, NIST SP 800-63B, RFC 9106 (Argon2), NIST SP 800-38D (GCM).

---

## 1. Alcance y Requisitos Funcionales (RF-01 a RF-08)

SecureVault es un sistema de almacenamiento seguro de credenciales y notas privadas cifradas con control de acceso estricto y trazabilidad de eventos.

| ID | Requisito Funcional | Descripción de Seguridad | Mitigación Técnica Principal |
| :--- | :--- | :--- | :--- |
| **RF-01** | Registro con política de contraseña | Validación estricta de complejidad: longitud mínima 12 caracteres, al menos 1 mayúscula, 1 minúscula, 1 número, 1 símbolo especial. Prevención de listas negras y cadenas triviales. | Zod schema validation en servidor + hash con **Argon2id** ($m \ge 19456\text{ KiB}$, $t \ge 2$, $p = 1$). |
| **RF-02** | Login y Logout seguro | Autenticación robusta con protección contra fuerza bruta y fijación de sesión. Logout invalida sesión/tokens de forma determinista en servidor. | Cookies `HttpOnly; Secure; SameSite=Strict`, prefijo `__Host-` en producción, rate-limiting con bloqueo exponencial y revocación activa. |
| **RF-03** | Control de Roles (RBAC) en Servidor | Roles `USER` y `ADMIN` verificados estrictamente en cada endpoint de backend. Prohibido confiar en cabeceras o payloads provistos por el cliente. | Middleware de autorización determinista `requireRole(['ADMIN'])`, validando claims contra BD o JWT firmado con HMAC-SHA256 / Ed25519. |
| **RF-04** | CRUD de Notas Privadas y prevención de IDOR | Cada usuario solo puede listar, leer, actualizar o eliminar sus propias notas. Los identificadores deben ser UUIDv4 o consultados con cláusula de tenencia obligatoria. | Scoping forzado en base de datos: `SELECT * FROM notes WHERE id = ? AND userId = ?`. Nunca confiar únicamente en el `id` de la nota. |
| **RF-05** | Cifrado y Enmascaramiento de Campo Sensible | Notas y campos de alto impacto se cifran en reposo mediante esquema autenticado. En lecturas parciales o registros de log, los datos sensibles se enmascaran (e.g. `****-1234`). | **AES-256-GCM** (`node:crypto`): IV aleatorio de 12 bytes por registro + AuthTag de 16 bytes. Serialización: `iv:authTag:ciphertext`. Función de enmascaramiento unidireccional para salidas no privilegiadas. |
| **RF-06** | Recuperación de contraseña segura | Generación de token con CSPRNG de alta entropía. Expiración breve (15 min) y consumo de un solo uso. La base de datos nunca almacena el token en texto claro. | Token: `crypto.randomBytes(32).toString('hex')`. En DB: `SHA-256(token)`, `expiresAt`, `used = false`. Validación con `crypto.timingSafeEqual()`. |
| **RF-07** | Panel de Administrador y Bitácora de Auditoría | Listado de usuarios y bitácora de auditoría inmutable/tamper-evident para eventos de seguridad. Prohibido registrar contraseñas, tokens o datos sensibles sin enmascarar. | Schema de auditoría estructurado: `{ id, eventType, userId, ipAddress, userAgent, metadata, timestamp }`. Sanitización preventiva de PII en logger. |
| **RF-08** | Endpoint de Salud Seguro (`GET /health`) | Monitoreo de disponibilidad (`status: ok`) sin fuga de información interna (evitar disclosure de stack, versiones de Node/Express, arquitectura de SO o uptime detallado). | Respuesta minimalista JSON fija `{"status": "UP", "timestamp": "..."}`. Eliminación global de cabeceras de fingerprinting (`X-Powered-By`). |

---

## 2. Cobertura OWASP Top 10:2025

- **A01:2025 - Broken Access Control**: Mitigado con RBAC estricto validado en servidor y consultas SQL con forzado de `userId` en todas las operaciones sobre `notes` (prevención de IDOR/BOLA).
- **A02:2025 - Cryptographic Failures**: Mitigado con Argon2id para contraseñas, AES-256-GCM con IV único de 12 bytes y AuthTag de 16 bytes para datos en reposo, SHA-256 para tokens de reseteo, y `crypto.timingSafeEqual` para comparaciones. Prohibidos MD5, SHA-1, AES-ECB y reutilización de IVs.
- **A03:2025 - Injection**: Mitigado mediante consultas preparadas con parámetros vinculados (Prepared Statements) en SQLite y esquemas de validación Zod en todos los inputs.
- **A04:2025 - Insecure Design**: Mitigado mediante modelo de amenazas STRIDE, principio de mínimo privilegio y defensa en profundidad.
- **A05:2025 - Security Misconfiguration**: Mitigado con cabeceras Helmet (HSTS, CSP, noSniff, frameguard), cookies `SameSite=Strict`, `Secure`, `HttpOnly`, y remoción de `X-Powered-By`.
- **A06:2025 - Vulnerable and Outdated Components**: Mitigado mediante auditorías automáticas de dependencias (`npm audit`), fijación de versiones y uso de imágenes base mínimas/endurecidas.
- **A07:2025 - Identification and Authentication Failures**: Mitigado con política de contraseñas robusta, rate limiting en `/auth/*`, tokens criptográficos de un solo uso con expiración y destrucción de sesión en logout.
- **A08:2025 - Software and Data Integrity Failures**: Mitigado mediante el tag de autenticación (AuthTag) de 16 bytes de AES-GCM (cualquier modificación no autorizada de datos en reposo invalida la lectura) y firmas criptográficas en tokens.
- **A09:2025 - Security Logging and Monitoring Failures**: Mitigado con tabla dedicada `security_audit_logs` que registra eventos clave (autenticación fallida/exitosa, acceso denegado, modificaciones críticas) con IP, timestamp UTC y detalles sanitizados (cero passwords ni tokens en logs).
- **A10:2025 - Server-Side Request Forgery & Next-Gen Flaws**: Mitigado al no admitir URLs arbitrarias provistas por el usuario y manteniendo el endpoint `/health` completamente aislado y sin llamadas a red salientes.
