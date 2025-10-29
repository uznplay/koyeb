# Use Node.js 20 Alpine (lightweight)
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy all source code
COPY . .

# Create certs directory (certificates will be generated at runtime)
RUN mkdir -p /app/certs && chmod 755 /app/certs

# Set production environment
ENV NODE_ENV=production

# Expose port
EXPOSE 8080

# Start the proxy
CMD ["node", "index.js"]

