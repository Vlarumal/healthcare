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

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set ownership and permissions
RUN chown -R appuser:appgroup /app
USER appuser

COPY --from=builder /app/package*.json ./
RUN npm install --omit=dev --ignore-scripts
COPY --from=builder /app/build ./build

# Keys will be mounted via secrets at runtime
EXPOSE 3001
CMD ["node", "build/index.js"]