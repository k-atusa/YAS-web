# syntax=docker/dockerfile:1.8

ARG NODE_VERSION=25

FROM node:${NODE_VERSION}-bookworm-slim AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
COPY frontend/tsconfig*.json ./
COPY frontend/vite.config.ts ./
COPY frontend/index.html ./
ENV NODE_ENV=development
RUN npm install --include=dev
COPY frontend/src ./src
COPY frontend/public ./public
ARG VITE_API_BASE_URL=/api
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
RUN npm run build

FROM node:${NODE_VERSION}-bookworm-slim AS backend-build
WORKDIR /app/backend
COPY backend/package*.json ./
COPY backend/tsconfig.json ./
ENV NODE_ENV=development
RUN npm install --include=dev
COPY backend/src ./src
COPY backend/src/types ./src/types
RUN npm run build

FROM node:${NODE_VERSION}-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=7000
COPY backend/package*.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY --from=backend-build /app/backend/dist ./dist
COPY --from=frontend-build /app/frontend/dist ./public
ENV FRONTEND_DIST=/app/public
EXPOSE 7000
CMD ["node", "dist/server.js"]
