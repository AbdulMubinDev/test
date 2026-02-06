FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 5432 6379

CMD ["nginx", "-g", "daemon off;"]

