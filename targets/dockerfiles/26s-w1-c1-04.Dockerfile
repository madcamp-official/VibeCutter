FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY public ./public
COPY server ./server
COPY data ./data

ENV PORT=3000
EXPOSE 3000

CMD ["node", "server/index.js"]
