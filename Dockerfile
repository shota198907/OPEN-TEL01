FROM node:20-slim

RUN apt-get update &&     apt-get upgrade -y &&     apt-get install -y --no-install-recommends dumb-init &&     rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY . .

RUN useradd -m -u 1001 -s /bin/bash appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]
