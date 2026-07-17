FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
ENV DATABASE_URL=postgresql://vibecutter:vibecutter@database:5432/concerts
ENV DIRECT_URL=postgresql://vibecutter:vibecutter@database:5432/concerts
ENV NEXT_PUBLIC_SUPABASE_URL=https://supabase.invalid
ENV NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=local-placeholder
RUN pnpm build

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
COPY --from=build /app ./
ENV NODE_ENV=production
EXPOSE 3000
CMD ["sh", "-c", "pnpm prisma:deploy && pnpm db:seed && pnpm start"]
