FROM node:22-alpine

WORKDIR /app

COPY .vibecutter/targets/sources/26s-w1-c3-03/package.json .vibecutter/targets/sources/26s-w1-c3-03/package-lock.json ./
RUN npm ci --omit=dev && npm install --omit=dev socket.io-client@4.7.5

COPY .vibecutter/targets/sources/26s-w1-c3-03/ ./
COPY targets/scripts/26s-w1-c3-03-smoke.js /opt/vibecutter/26s-w1-c3-03-smoke.js

ENV PORT=3000
ENV FIREBASE_SERVICE_ACCOUNT_PATH=/run/secrets/firebase-service-account.json
ENV NODE_PATH=/app/node_modules
EXPOSE 3000

CMD ["node", "server.js"]
