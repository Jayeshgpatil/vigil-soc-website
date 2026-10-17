# VGIL — Security Operations & Threat Monitoring
#
# Node 22 is the floor: the database layer uses node:sqlite, which landed in
# 22.5. Alpine keeps the image small and needs no build toolchain, because
# nothing here compiles a native module.

FROM node:22-alpine

# dumb-init makes PID 1 forward SIGTERM properly, so the graceful shutdown in
# server.js actually runs and the SQLite WAL gets checkpointed on stop.
RUN apk add --no-cache dumb-init

WORKDIR /app

# Dependencies first, so a code change does not invalidate the install layer.
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY server ./server
COPY public ./public

# The database and signing key live on a mounted volume, not in the image.
RUN mkdir -p /data && chown -R node:node /data /app
ENV VGIL_DB=/data/vgil.db \
    NODE_ENV=production \
    PORT=3000

USER node
EXPOSE 3000

# Readiness, not liveness: this fails if the database cannot be queried, so an
# orchestrator pulls the container out of rotation instead of just bouncing it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "--disable-warning=ExperimentalWarning", "server/server.js"]
