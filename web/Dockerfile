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

# busybox wget ships in nginx:alpine; curl does not. 127.0.0.1, not localhost:
# Alpine's musl resolver tries ::1 (IPv6) first for "localhost", and nginx
# below only listens on 0.0.0.0 (IPv4) — verified this healthcheck has always
# failed with "Connection refused" for that reason, pre-existing and
# independent of the non-root change below (reproduced against the original
# root-running image too).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider http://127.0.0.1/health || exit 1

# Run as nginx:alpine's own built-in non-root user (uid 101) rather than root.
# The Helm deployment (deploy/helm/keyorix/templates/web-deployment.yaml)
# already assumed this — it sets runAsUser: 101 and grants
# CAP_NET_BIND_SERVICE so nginx can still bind port 80 as non-root — but that
# Kubernetes securityContext only applies under the Helm chart; plain
# `docker run`/`docker compose` had no such override, so the container ran as
# root there. This makes non-root the image's own default across every
# deployment path, matching what the chart already assumed.
#
# The base image's /var/cache/nginx, /var/log/nginx, and /run are root-owned
# (verified: nginx fails at startup with "mkdir /var/cache/nginx/client_temp:
# Permission denied" without this) — nginx's master process creates its
# temp/cache subdirs and pid file at startup, and our nginx.conf writes real
# log files under /var/log/nginx rather than the base image's default
# symlink-to-stdout/stderr setup, so both need to be writable by uid 101
# before dropping to it.
RUN chown -R nginx:nginx /var/cache/nginx /var/log/nginx /run
USER nginx

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
