FROM python:3.13-slim AS api-runtime
WORKDIR /app
RUN pip install --no-cache-dir fastapi 'uvicorn[standard]' sqlalchemy passlib bcrypt==3.2.0
COPY backend/ ./backend/
EXPOSE 8000
CMD ["uvicorn", "backend.src.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM node:22-bookworm-slim AS frontend-build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG VITE_API_URL=/api
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:1.27-alpine AS frontend-runtime
COPY --from=frontend-build /app/dist /usr/share/nginx/html
EXPOSE 80
