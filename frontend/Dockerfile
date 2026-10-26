# The frontend: a production build served by nginx. Built by docker-compose.yml, see DEPLOYMENT.md.

FROM node:22.23.4-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
# Vite bakes the API address into the JavaScript at build time.
ARG VITE_API_URL=""
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:1.30.6-alpine
# nginx fills ${API_URL} in the template when the container starts (for the CSP header).
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
