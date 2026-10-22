# A web server that presents a self-signed certificate and sets no security headers, so
# reconscope has something to flag.
FROM nginx:1.27-alpine
RUN apk add --no-cache openssl \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
       -keyout /etc/nginx/tls.key -out /etc/nginx/tls.crt -subj "/CN=web.lab.test"
COPY default.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
