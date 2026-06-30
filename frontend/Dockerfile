FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
RUN npm install -g serve
COPY --from=build /app/dist ./dist

RUN adduser -S -D -H appuser && chown -R appuser /app

USER appuser

EXPOSE 5173
CMD ["serve", "-s", "dist", "-l", "5173"]
