FROM node:22-bookworm-slim AS frontend-build
WORKDIR /app
COPY frontend/codebee-frontend/package.json frontend/codebee-frontend/package-lock.json ./
RUN npm ci
COPY frontend/codebee-frontend/ ./
RUN npm run build

FROM python:3.13-slim AS runtime
WORKDIR /app/backend
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY --from=frontend-build /app/dist /app/frontend/codebee-frontend/dist
EXPOSE 8000
CMD ["sh", "-c", "python manage.py migrate --run-syncdb --noinput && python manage.py collectstatic --noinput && daphne -b 0.0.0.0 -p 8000 config.asgi:application"]
