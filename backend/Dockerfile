# syntax=docker/dockerfile:1.8
FROM node:26-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
COPY tsconfig*.json ./
RUN npm install
COPY src ./src
RUN npm run build

FROM node:26-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=7001

# Install Tor
RUN apt-get update && apt-get install -y tor && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY start.sh ./start.sh
RUN chmod +x ./start.sh

EXPOSE 7001
CMD ["./start.sh"]
