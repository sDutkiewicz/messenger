FROM nginx:1.25-alpine

WORKDIR /usr/share/nginx/html

# Copy frontend files
COPY *.html ./
COPY *.js ./
COPY *.css ./

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
