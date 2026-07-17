FROM node:22-bookworm-slim AS dependencies
WORKDIR /workspace
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl \
  && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
COPY backend/package.json backend/package.json
COPY frontend/package.json frontend/package.json
RUN npm ci

FROM dependencies AS workspace
COPY . .
RUN npm --workspace campus-wakppuball-backend run prisma:generate

FROM workspace AS api-build
RUN npm run build --workspace campus-wakppuball-backend

FROM api-build AS api-runtime
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "backend/dist/server.js"]

FROM workspace AS frontend-build
ARG VITE_API_BASE_URL
ARG VITE_ENABLE_MOCKS=false
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_ENABLE_MOCKS=$VITE_ENABLE_MOCKS
RUN npm run build --workspace campus-wakppuball-frontend

FROM nginx:1.27-alpine AS frontend-runtime
COPY --from=frontend-build /workspace/frontend/dist /usr/share/nginx/html
EXPOSE 80
