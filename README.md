# 🛡️ SecureVault — Laboratorio de Seguridad en Aplicaciones (AppSec)

[![OWASP Top 10:2025](https://img.shields.io/badge/OWASP-Top%2010%3A2025-blue.svg)](https://owasp.org)
[![Node.js](https://img.shields.io/badge/Node.js-24%20LTS-green.svg)](https://nodejs.org)
[![React](https://img.shields.io/badge/React-19%20%2B%20Vite-61dafb.svg)](https://react.dev)
[![MySQL](https://img.shields.io/badge/Database-MySQL%20%2F%20SQLite-orange.svg)](https://www.mysql.com)
[![Deployment](https://img.shields.io/badge/Netlify-Deployed-00ad9f.svg)](https://sweet-donut-deeef8.netlify.app)

Sistema de gestión y almacenamiento seguro de secretos y notas privadas con arquitectura desacoplada, autenticación robusta, control de acceso basado en roles (RBAC) y cifrado autenticado en reposo con **AES-256-GCM**.

🌐 **Despliegue en Vivo (Frontend React en Netlify):**  
[https://sweet-donut-deeef8.netlify.app](https://sweet-donut-deeef8.netlify.app)

---

## 📋 Requerimientos Funcionales y de Seguridad Implementados

| Requerimiento | Descripción Técnica | Mitigación OWASP / Estándar |
| :--- | :--- | :--- |
| **RF-01: Autenticación Robusta** | Política de contraseñas estricta (mín. 12 caracteres, mayúsculas, minúsculas, números y símbolos). Hashing con **Bcrypt (cost factor 12)** y sal aleatoria por usuario. | *OWASP A07: Identification and Authentication Failures* |
| **RF-02: Gestión de Sesión Segura** | Tokens de sesión emitidos en cookies con directivas `HttpOnly`, `SameSite=Strict`, `Secure` y expiración a los 60 minutos. | *OWASP A01: Broken Access Control* |
| **RF-03: Control de Acceso (RBAC)** | Roles diferenciados (`ADMIN` y `USER`). Protección estricta en servidor para rutas `/admin/*`. Mitigación de IDOR comprobando propiedad de recursos en cada consulta. | *OWASP A01: Broken Access Control* |
| **RF-04: Cifrado en Reposo** | Cifrado simétrico autenticado **AES-256-GCM** con IV aleatorio de 12 bytes por nota y Authentication Tag de 16 bytes para prevenir alteraciones de texto cifrado. | *OWASP A02: Cryptographic Failures* |
| **RF-05: Enmascaramiento de Datos** | Enmascaramiento de datos sensibles en listados públicos (`****-****-****-4444`). Descifrado bajo demanda solo para el propietario autorizado. | *OWASP A02: Cryptographic Failures* |
| **RF-06: Recuperación Segura** | Flujo de reset de contraseña con tokens criptográficos de un solo uso generados con CSPRNG (32 bytes), almacenados en hash **SHA-256** y validez de 15 minutos. | *OWASP A07: Identification and Authentication Failures* |
| **RF-07: Bitácora de Auditoría** | Registro inmutable de eventos de seguridad (inicios de sesión, intentos fallidos, accesos denegados). Sanitización automática de contraseñas y tokens (`[REDACTED_BY_AUDIT_POLICY]`). | *OWASP A09: Security Logging and Monitoring Failures* |
| **RF-08: Hardening y Sanidad** | Cabeceras de seguridad estrictas (**Helmet** con CSP, HSTS, X-Frame-Options), limitador de tasa (**Rate Limiting**), validación de esquemas con **Zod**, y endpoint `/health` opaco. | *OWASP A05: Security Misconfiguration* |

---

## 🔑 Credenciales Predeterminadas para Pruebas

### Usuario Administrador:
* **Email:** `admin@vault.local`
* **Contraseña:** `Admin#Vault2026!`
* **Rol:** `ADMIN` *(Acceso a la bóveda privada, lista de usuarios y bitácora de auditoría)*

### Registro de Nuevos Usuarios:
* Puedes registrar nuevos usuarios regulares desde la pestaña **"Registrarse"**.
* La contraseña debe cumplir con la política: mínimo 12 caracteres, mayúscula, minúscula, número y símbolo especial (ejemplo: `Usuario#Vault2026!`).

---

## 🏗️ Arquitectura del Sistema

```
laboratorio-seguridad/
├── backend/                  # Servidor API REST (Node.js 24 + Express)
│   ├── src/
│   │   ├── config/           # Variables de entorno validadas con Zod
│   │   ├── crypto/           # Motores AES-256-GCM y hashing SHA-256 / Bcrypt
│   │   ├── db/               # Adaptador dual MySQL (mysql2 pool) / SQLite (tests)
│   │   ├── middleware/       # Autenticación JWT HttpOnly, RBAC y Rate Limiting
│   │   ├── routes/           # Endpoints auth, notes, admin, health
│   │   └── services/         # Lógica de negocio y auditoría sanitizada
│   └── tests/                # 19 pruebas automatizadas de seguridad
├── frontend/                 # Aplicación SPA (React 19 + Vite 6)
│   ├── src/                  # Componentes React y motor criptográfico WebCrypto
│   └── dist/                 # Build de producción optimizado para Netlify
├── docker/                   # Dockerfiles con principio de menor privilegio (non-root)
├── netlify.toml              # Configuración de despliegue continuo en Netlify
└── README.md
```

---

## 🚀 Puesta en Marcha Local

### 1. Configurar Base de Datos (MySQL)
Asegúrate de tener un servicio MySQL corriendo en el puerto 3306 (por ejemplo `securevault_db`, usuario `root`, contraseña `1234`). El backend creará la base de datos y tablas automáticamente en su primer inicio.

### 2. Iniciar el Backend
```bash
cd backend
npm install
npm run dev
```
El servidor responderá en `http://localhost:3000` (o HTTPS en `https://localhost:8443`).

### 3. Ejecutar Pruebas Automatizadas
El proyecto cuenta con **19 pruebas unitarias y de integración** que validan la seguridad de extremo a extremo:
```bash
cd backend
npm test
```
*Todas las pruebas se ejecutan de manera aislada utilizando `node:sqlite` en memoria para no alterar la base de datos de producción.*

### 4. Iniciar el Frontend Localmente
```bash
cd frontend
npm install
npm run dev
```
Abre en tu navegador `http://localhost:5173`.

---

## 🔒 Despliegue en Netlify
El repositorio está configurado con despliegue continuo en **Netlify**.  
Cada commit a la rama `main` compila y publica automáticamente la aplicación:
* **Build command:** `cd frontend && npm install && npm run build`
* **Publish directory:** `frontend/dist`
* **URL:** [https://sweet-donut-deeef8.netlify.app](https://sweet-donut-deeef8.netlify.app)
