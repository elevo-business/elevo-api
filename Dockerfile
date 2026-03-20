FROM node:20-alpine

WORKDIR /app

COPY package.json ./
# Keine npm install nötig — zero dependencies!

COPY server.js ./

EXPOSE 3000

USER node

CMD ["node", "server.js"]
