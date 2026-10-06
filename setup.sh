#!/bin/bash
# ============================================================
#  ThreatMapper – One-Shot EC2 Setup Script
#  Run as:  chmod +x setup.sh && ./setup.sh <YOUR_EC2_PUBLIC_IP>
# ============================================================

EC2_IP="${1:-$(curl -s http://checkip.amazonaws.com)}"
echo "==> EC2 Public IP detected: $EC2_IP"

# ── 1. System dependencies ───────────────────────────────────
echo "==> Installing system packages..."
sudo apt-get update -y
sudo apt-get install -y python3 python3-pip python3-venv nodejs npm git nginx curl

# Check Node version – need 18+
NODE_VER=$(node -v | cut -c2- | cut -d. -f1)
if [ "$NODE_VER" -lt 18 ]; then
    echo "==> Upgrading Node.js to v20..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

# ── 2. Python virtual environment ───────────────────────────
echo "==> Setting up Python venv..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# ── 3. Build React frontend ──────────────────────────────────
echo "==> Building React frontend..."
cd threatmapper-react
REACT_APP_API_URL="http://${EC2_IP}:8001" npm install --legacy-peer-deps
REACT_APP_API_URL="http://${EC2_IP}:8001" npm run build
cd ..

# ── 4. Configure Nginx to serve React build + proxy API ─────
echo "==> Configuring Nginx..."
sudo tee /etc/nginx/sites-available/threatmapper > /dev/null <<NGINX_CONF
server {
    listen 80;
    server_name ${EC2_IP};

    # React frontend
    root $(pwd)/threatmapper-react/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # API proxy → FastAPI on port 8001
    location /api/ {
        proxy_pass http://127.0.0.1:8001/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        add_header Access-Control-Allow-Origin *;
    }
}
NGINX_CONF

sudo ln -sf /etc/nginx/sites-available/threatmapper /etc/nginx/sites-enabled/threatmapper
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

# ── 5. Start FastAPI backend ─────────────────────────────────
echo "==> Starting FastAPI backend on port 8001..."
source venv/bin/activate
nohup uvicorn api.app:app --host 0.0.0.0 --port 8001 --reload > api.log 2>&1 &
echo "FastAPI PID: $!"
echo $! > api.pid

echo ""
echo "============================================"
echo " ThreatMapper is running!"
echo " Frontend : http://${EC2_IP}"
echo " API      : http://${EC2_IP}:8001"
echo " API Docs : http://${EC2_IP}:8001/docs"
echo "============================================"
