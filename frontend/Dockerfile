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
