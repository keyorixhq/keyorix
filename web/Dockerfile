# Build stage — the SPA is built with pnpm (the repo's package manager) on Node 22.
# All dependencies are needed (Vite et al. are devDependencies), so this is a
# full install, not --prod.
FROM node:22-alpine AS builder
RUN npm install -g pnpm@11
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

# Production stage — nginx serves the static bundle and reverse-proxies the API
# (/api/ and /auth/) to the backend service. See nginx.conf.
FROM nginx:alpine AS production
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=builder /app/dist /usr/share/nginx/html

# busybox wget ships in nginx:alpine; curl does not.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost/health || exit 1

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
