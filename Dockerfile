FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY bin ./bin
COPY src ./src
# Starts and answers MCP introspection without any account connected.
# Real use needs your OAuth client and an OS keyring (or GMAIL_TIDY_KEY).
ENTRYPOINT ["node", "bin/gmail-tidy-mcp.js"]
