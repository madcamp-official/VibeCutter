FROM node:22-alpine AS dependencies

WORKDIR /workspace

COPY package.json package-lock.json ./
COPY client/package.json client/package.json
COPY server/package.json server/package.json
COPY shared/package.json shared/package.json
RUN npm ci && apk add --no-cache bash

FROM dependencies AS workspace

COPY . .
RUN npm --workspace @madcade/server run prisma:generate

FROM workspace AS build

ARG VITE_GOOGLE_CLIENT_ID
ENV VITE_GOOGLE_CLIENT_ID=$VITE_GOOGLE_CLIENT_ID
RUN npm --workspace @madcade/client run build

FROM workspace AS runtime

COPY --from=build /workspace/client/dist /workspace/client/dist

ENV NODE_ENV=production
EXPOSE 3000
CMD ["npm", "--workspace", "@madcade/server", "run", "start"]
