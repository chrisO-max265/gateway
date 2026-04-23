FROM node:20-slim

# Install wireproxy and dependencies
RUN apt-get update && apt-get install -y wget curl && \
    wget -O /usr/local/bin/wireproxy https://github.com/octeep/wireproxy/releases/download/v1.0.9/wireproxy_linux_amd64 && \
    chmod +x /usr/local/bin/wireproxy && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all source files
COPY gateway.js .

# Create config directory and files
RUN mkdir -p config data logs

# Create wireproxy-base.conf
RUN cat > wireproxy-base.conf << 'EOF'
[Interface]
PrivateKey = 0LUaKbzJnD3D7RQU+0IhD4v7Mdljs1rLpzlb0IX4X00=
Address = 2a11:6c7:f06:54::2/64
DNS = 2606:4700:4700::1111

[Peer]
PublicKey = UjxJQ7r//mwL/bKYg2LLM7xUmIg9q0BEsbIXJEc6zHo=
AllowedIPs = 2000::/3
Endpoint = ENDPOINT_PLACEHOLDER:20011
PersistentKeepalive = 15
EOF

# Create config/wireproxy.conf
RUN cat > config/wireproxy.conf << 'EOF'
[Interface]
PrivateKey = 0LUaKbzJnD3D7RQU+0IhD4v7Mdljs1rLpzlb0IX4X00=
Address = 2a11:6c7:f06:54::2/64
DNS = 2606:4700:4700::1111

[Peer]
PublicKey = UjxJQ7r//mwL/bKYg2LLM7xUmIg9q0BEsbIXJEc6zHo=
AllowedIPs = 2000::/3
Endpoint = ENDPOINT_PLACEHOLDER:20011
PersistentKeepalive = 15

[Socks5]
BindAddress = 127.0.0.1:8300
EOF

# Create config.json
RUN cat > config.json << 'EOF'
{
  "wireproxy": { "instances": 3 },
  "batch": { "window_ms": 200, "max_queue": 50000 },
  "timeouts": { "client_idle_ms": 300000, "process_lifetime_ms": 86400000 },
  "tiers": {
    "basic": { "bandwidth_limit_gb": 50, "expiration_days": 30, "max_concurrent": 5, "rate_limit": 2 },
    "premium": { "bandwidth_limit_gb": 500, "expiration_days": 90, "max_concurrent": 50, "rate_limit": 20 }
  },
  "public_host": "PUBLIC_HOST_PLACEHOLDER"
}
EOF

# Create startup script that auto-updates Route64 endpoint
RUN cat > start.sh << 'EOF'
#!/bin/bash

# Get public IPv4 address of this container
PUBLIC_IP=$(curl -s -4 ifconfig.me || curl -s -4 ip.sb || curl -s -4 api.ipify.org)
echo "[STARTUP] Detected public IPv4: $PUBLIC_IP"

# Get public hostname from Northflank
PUBLIC_HOST=${PUBLIC_HOST:-"localhost:8330"}

# Update wireproxy configs with the correct endpoint
sed -i "s/ENDPOINT_PLACEHOLDER/$PUBLIC_IP/g" /app/wireproxy-base.conf
sed -i "s/ENDPOINT_PLACEHOLDER/$PUBLIC_IP/g" /app/config/wireproxy.conf
sed -i "s/PUBLIC_HOST_PLACEHOLDER/$PUBLIC_HOST/g" /app/config.json

echo "[STARTUP] Updated Route64 endpoint to: $PUBLIC_IP:20011"
echo "[STARTUP] Public host set to: $PUBLIC_HOST"

# Start wireproxy (background)
/usr/local/bin/wireproxy -c /app/config/wireproxy.conf &

# Wait for wireproxy to initialize
sleep 3

# Start the gateway
exec node /app/gateway.js
EOF

RUN chmod +x start.sh

# Environment variables
ENV WIREPROXY_BIN=/usr/local/bin/wireproxy
ENV LISTEN_PORT=8330
ENV API_PORT=8331
ENV PREFIX=2a11:6c7:f06:54

EXPOSE 8330 8331

CMD ["/app/start.sh"]
