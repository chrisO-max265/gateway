FROM node:20-slim
RUN apt-get update && apt-get install -y wget && \
    wget -O /usr/local/bin/wireproxy https://github.com/octeep/wireproxy/releases/download/v1.0.9/wireproxy_linux_amd64 && \
    chmod +x /usr/local/bin/wireproxy
WORKDIR /app
COPY gateway.js config.json wireproxy-base.conf ./
RUN mkdir -p config && echo '{}' > config/wireproxy.conf
ENV WIREPROXY_BIN=/usr/local/bin/wireproxy
ENV LISTEN_PORT=8330
ENV API_PORT=8331
ENV PREFIX=2a11:6c7:f06:54
EXPOSE 8330 8331
CMD node gateway.js