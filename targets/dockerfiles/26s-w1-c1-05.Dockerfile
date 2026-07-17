FROM gradle:8.14-jdk17 AS backend-build

WORKDIR /workspace
COPY --chown=gradle:gradle . .
RUN gradle --no-daemon bootJar

FROM eclipse-temurin:17-jre-jammy AS backend-runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=backend-build /workspace/build/libs/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

FROM node:22-alpine AS frontend-build

WORKDIR /workspace
ARG VITE_API_BASE_URL
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine AS frontend-runtime

COPY --from=frontend-build /workspace/dist /usr/share/nginx/html
EXPOSE 80
