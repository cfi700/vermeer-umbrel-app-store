FROM node:20-alpine

RUN apk add --no-cache vips-dev python3 make g++ libc6-compat

WORKDIR /app

COPY app/backend/package*.json ./app/backend/
RUN cd app/backend && npm install --production

COPY app/backend/ ./app/backend/
COPY app/frontend/ ./app/frontend/

RUN mkdir -p /data/photos /data/thumbs /data/sessions

ENV PORT=3000
ENV DATA_DIR=/data
ENV NODE_ENV=production

EXPOSE 3000

WORKDIR /app/app/backend
CMD ["node", "server.js"]
