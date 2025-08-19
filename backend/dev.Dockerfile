# Stage 1: Build
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install --include=dev
COPY . .
RUN npm run build

# Stage 2: Production
FROM node:22-alpine
WORKDIR /app
COPY --from=builder /app/package*.json ./
RUN npm install --omit=dev
COPY --from=builder /app/build ./build
COPY --from=builder /app/keys ./keys
EXPOSE 3000
CMD ["node", "build/index.js"]