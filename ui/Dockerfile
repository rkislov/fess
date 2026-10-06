FROM node:20-alpine AS builder

WORKDIR /app
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
ARG NUXT_PUBLIC_API_BASE=/api/v1
ARG NUXT_PUBLIC_UI_AUTH_ENABLED=true
ARG NUXT_PUBLIC_UI_USER=admin
ARG NUXT_PUBLIC_UI_PASSWORD=fessfess
ENV NUXT_PUBLIC_API_BASE=$NUXT_PUBLIC_API_BASE
ENV NUXT_PUBLIC_UI_AUTH_ENABLED=$NUXT_PUBLIC_UI_AUTH_ENABLED
ENV NUXT_PUBLIC_UI_USER=$NUXT_PUBLIC_UI_USER
ENV NUXT_PUBLIC_UI_PASSWORD=$NUXT_PUBLIC_UI_PASSWORD
RUN npm run build

FROM nginx:1.27-alpine
COPY ui/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/.output/public /usr/share/nginx/html
EXPOSE 80
