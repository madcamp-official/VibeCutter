FROM node:22-bookworm-slim AS builder

ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json .npmrc ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/database/package.json packages/database/package.json
COPY packages/shared/package.json packages/shared/package.json
RUN pnpm install --frozen-lockfile

COPY apps/ ./apps/
COPY packages/ ./packages/
COPY uploads/ ./uploads/

ENV NEXT_PUBLIC_API_BASE_URL=/api
ENV API_PROXY_TARGET=http://api:4000
RUN sed -i 's/const width = gridElement.clientWidth;/if (!gridElement) return; const width = gridElement.clientWidth;/' apps/web/app/page.tsx
RUN pnpm db:generate \
    && pnpm --filter @maeari/shared build \
    && pnpm --filter @maeari/database build \
    && pnpm --filter @maeari/api build \
    && pnpm --filter @maeari/web build

FROM builder AS api-runtime
EXPOSE 4000
CMD ["sh", "-c", "pnpm db:deploy && pnpm --filter @maeari/api start"]

FROM builder AS web-runtime
EXPOSE 3000
CMD ["pnpm", "--filter", "@maeari/web", "start"]
