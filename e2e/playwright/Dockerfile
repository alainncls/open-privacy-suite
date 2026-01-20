FROM mcr.microsoft.com/playwright:v1.48.0-jammy

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies
RUN npm install

# Copy source files
COPY . .

# Default command runs tests
CMD ["npm", "test"]
