FROM node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
COPY packages ./packages
COPY infrastructure ./infrastructure
COPY scripts ./scripts
RUN npm ci --omit=dev && npm cache clean --force

USER node
EXPOSE 8080
CMD ["node", "--experimental-strip-types", "packages/api/src/main.ts"]
