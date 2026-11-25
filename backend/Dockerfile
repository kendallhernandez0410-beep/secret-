# syntax=docker/dockerfile:1.4
# ==============================================================================
# SecureVault - Multi-Stage Hardened Dockerfile
# Base: Node.js 24 Alpine | Usuario no privilegiado (non-root)
# ==============================================================================

# ------------------------------------------------------------------------------
# Etapa 1: Dependencias y Auditoría
# ------------------------------------------------------------------------------
FROM node:24-alpine AS deps
WORKDIR /app

# Instalar dependencias del sistema mínimas requeridas
RUN apk add --no-cache libc6-compat

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# ------------------------------------------------------------------------------
# Etapa 2: Imagen Final de Producción Endurecida
# ------------------------------------------------------------------------------
FROM node:24-alpine AS runner
WORKDIR /app

# Hardening del SO del contenedor:
# 1. Definir entorno de producción estricto
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
ENV TRUST_PROXY=true

# 2. Crear directorio de datos con permisos estrictos para el usuario 'node'
RUN mkdir -p /app/data && chown -R node:node /app

# 3. Copiar dependencias de producción y código fuente
COPY --from=deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --chown=node:node src/ ./src/

# 4. Cambiar a usuario no-root por principio de mínimo privilegio (CIS Benchmark)
USER node

# 5. Exponer puerto interno (nunca expuesto a la WAN directamente)
EXPOSE 3000

# 6. Healthcheck nativo de contenedor hacia el endpoint opaco /health
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

# 7. Inicio de la aplicación
CMD ["node", "src/server.js"]
