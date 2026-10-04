# Stage 1: install deps, generate Prisma client, typecheck
FROM node:22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

COPY package.json package-lock.json ./
COPY prisma ./prisma

RUN npm ci && npx prisma generate

COPY . .

RUN npm run typecheck

# Stage 2: lean runtime image (tsx — app uses .ts imports / noEmit)
FROM node:22-alpine AS production

WORKDIR /app

RUN apk add --no-cache openssl libc6-compat wget \
  && addgroup -g 1001 -S nodejs \
  && adduser -S tefu -u 1001

COPY --from=builder --chown=tefu:nodejs /app/package.json ./package.json
COPY --from=builder --chown=tefu:nodejs /app/package-lock.json ./package-lock.json
COPY --from=builder --chown=tefu:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=tefu:nodejs /app/prisma ./prisma
COPY --from=builder --chown=tefu:nodejs /app/src ./src
COPY --from=builder --chown=tefu:nodejs /app/tsconfig.json ./tsconfig.json
COPY --from=builder --chown=tefu:nodejs /app/docker-entrypoint.sh ./docker-entrypoint.sh

RUN chmod +x ./docker-entrypoint.sh \
  && mkdir -p storage \
  && chown -R tefu:nodejs storage

USER tefu

EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:4000/api/v1/health >/dev/null || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["npx", "tsx", "src/server.ts"]
