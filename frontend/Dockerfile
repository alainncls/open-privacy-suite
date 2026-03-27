# ── Dev image (Vite dev server with hot-reload) ───────────────────────────────
FROM node:20-alpine AS dev

RUN apk add --no-cache wget

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --ignore-scripts && npm rebuild esbuild

COPY . .

EXPOSE 5173
CMD ["npm", "run", "dev"]

# ── Production build ──────────────────────────────────────────────────────────
FROM node:20-alpine AS builder-prod

WORKDIR /app

# Accept VITE_* env vars as build args (baked into static JS at build time).
# SECURITY: Never pass secrets here — everything becomes part of the JS bundle.
ARG VITE_ALLOW_MOCK_LOGIN=false
ARG VITE_BACKEND_URL=
ARG VITE_FEATURE_GOVERNANCE_UI=false

COPY package.json package-lock.json* ./
RUN npm install --ignore-scripts && npm rebuild esbuild

COPY . .
RUN npm run build

# ── Production image (nginx serving compiled static files) ────────────────────
FROM nginx:alpine AS prod

COPY --from=builder-prod /app/dist /usr/share/nginx/html
COPY nginx.prod.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

# ── E2E image (prod build + API proxy to backend) ────────────────────────────
FROM nginx:alpine AS e2e

RUN apk add --no-cache wget

COPY --from=builder-prod /app/dist /usr/share/nginx/html
COPY nginx.e2e.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
