FROM nginx:1.27-alpine

# Install nginx-extras for headers-more module
RUN apk add --no-cache nginx-extras

COPY nginx.conf /etc/nginx/nginx.conf

# Copy custom 404 page
COPY 404.html /usr/share/nginx/html/404.html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
