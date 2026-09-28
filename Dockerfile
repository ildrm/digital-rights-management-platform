FROM node:26-bookworm-slim@sha256:662933cf47f013bc8e4beb31a6116448427a82057ba7c42c97e4c5ba766504c2

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
COPY packages ./packages
RUN npm ci --omit=dev && npm cache clean --force

USER node
EXPOSE 8080
CMD ["node", "--experimental-strip-types", "packages/api/src/main.ts"]
