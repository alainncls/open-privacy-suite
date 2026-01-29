FROM node:20-alpine

# Install wget for healthcheck
RUN apk add --no-cache wget

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies (skip native build scripts - bufferutil/utf-8-validate are optional)
RUN npm install --ignore-scripts && npm rebuild esbuild

# Copy source code
COPY . .

# Expose Vite dev server port
EXPOSE 5173

# Start dev server
CMD ["npm", "run", "dev"]
