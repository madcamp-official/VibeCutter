FROM node:22-alpine AS dependencies

WORKDIR /workspace
COPY package.json package-lock.json ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/shared/package.json packages/shared/package.json
RUN npm ci

FROM dependencies AS workspace

COPY . .

FROM workspace AS api-build

RUN npm run build --workspace @latestock/shared \
    && npm run build --workspace @latestock/api

FROM api-build AS api-runtime

ENV NODE_ENV=production
EXPOSE 4000
CMD ["node", "apps/api/dist/index.js"]

FROM workspace AS web-build

ARG VITE_API_BASE_URL
ARG VITE_KAKAO_JS_KEY
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_KAKAO_JS_KEY=$VITE_KAKAO_JS_KEY
RUN npm run build --workspace @latestock/shared \
    && npm run build --workspace @latestock/web

FROM nginx:1.27-alpine AS web-runtime

COPY --from=web-build /workspace/apps/web/dist /usr/share/nginx/html
EXPOSE 80
