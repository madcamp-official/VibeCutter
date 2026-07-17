FROM node:22-alpine AS frontend-build

WORKDIR /app

ARG VITE_API_BASE_URL=
ARG VITE_GOOGLE_CLIENT_ID=p2-local-google-client.apps.googleusercontent.com
ARG VITE_KAKAO_REST_API_KEY=p2-local-kakao-key
ARG VITE_KAKAO_REDIRECT_URI=http://127.0.0.1:14031/oauth/kakao/callback
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
ENV VITE_GOOGLE_CLIENT_ID=${VITE_GOOGLE_CLIENT_ID}
ENV VITE_KAKAO_REST_API_KEY=${VITE_KAKAO_REST_API_KEY}
ENV VITE_KAKAO_REDIRECT_URI=${VITE_KAKAO_REDIRECT_URI}

COPY package.json package-lock.json ./
RUN npm install

COPY . .
RUN npm run build

FROM nginx:1.27-alpine

COPY --from=frontend-build /app/dist /usr/share/nginx/html
