#!/bin/bash
# ============================================================
#  ThreatMapper – One-Shot EC2 Setup Script
#  Supports both Amazon Linux (yum/dnf) and Ubuntu (apt)
#  Run as:  chmod +x setup.sh && ./setup.sh <YOUR_EC2_PUBLIC_IP>
# ============================================================

EC2_IP="${1:-$(curl -s http://checkip.amazonaws.com)}"
echo "==> EC2 Public IP detected: $EC2_IP"
PROJECT_DIR="$(pwd)"

# ── 1. Detect OS and install system packages ──────────────────
echo "==> Detecting OS and installing dependencies..."
if command -v apt-get &> /dev/null; then
    # Ubuntu / Debian
    sudo apt-get update -y
    sudo apt-get install -y python3 python3-pip python3-venv git nginx curl
    
    # Node.js 20
    NODE_VER=$(node -v 2>/dev/null | cut -c2- | cut -d. -f1 || echo "0")
    if [ "$NODE_VER" -lt 18 ]; then
        echo "==> Installing Node.js 20..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
    fi
elif command -v dnf &> /dev/null || command -v yum &> /dev/null; then
    # Amazon Linux 2023 / Amazon Linux 2 / RHEL / CentOS
    PKG_MGR="yum"
    command -v dnf &> /dev/null && PKG_MGR="dnf"
    
    sudo $PKG_MGR update -y
    sudo $PKG_MGR install -y python3 python3-pip git nginx curl
    
    # Node.js 20
    NODE_VER=$(node -v 2>/dev/null | cut -c2- | cut -d. -f1 || echo "0")
    if [ "$NODE_VER" -lt 18 ]; then
        echo "==> Installing Node.js 20..."
        curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
        sudo $PKG_MGR install -y nodejs
    fi
fi

# ── 2. Python virtual environment ───────────────────────────
echo "==> Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# ── 3. Build React frontend ──────────────────────────────────
echo "==> Building React frontend with API URL http://${EC2_IP}:8001..."
cd threatmapper-react
export REACT_APP_API_URL="http://${EC2_IP}:8001"
npm install --legacy-peer-deps
npm run build
cd "$PROJECT_DIR"

# Ensure nginx can read files in home directory
chmod o+x "$HOME"
chmod -R o+rx "$PROJECT_DIR/threatmapper-react/build"

# ── 4. Configure Nginx ───────────────────────────────────────
echo "==> Configuring Nginx..."
if [ -d "/etc/nginx/sites-available" ]; then
    # Ubuntu/Debian style
    sudo tee /etc/nginx/sites-available/threatmapper > /dev/null <<NGINX_CONF
server {
    listen 80 default_server;
    server_name _;

    root ${PROJECT_DIR}/threatmapper-react/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
NGINX_CONF
    sudo ln -sf /etc/nginx/sites-available/threatmapper /etc/nginx/sites-enabled/default
    sudo rm -f /etc/nginx/sites-enabled/threatmapper
    sudo ln -sf /etc/nginx/sites-available/threatmapper /etc/nginx/sites-enabled/threatmapper
else
    # Amazon Linux / CentOS style
    sudo tee /etc/nginx/conf.d/threatmapper.conf > /dev/null <<NGINX_CONF
server {
    listen 80 default_server;
    server_name _;

    root ${PROJECT_DIR}/threatmapper-react/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
NGINX_CONF
fi

sudo nginx -t && sudo systemctl restart nginx
sudo systemctl enable nginx

# ── 5. Start FastAPI backend ─────────────────────────────────
echo "==> Starting FastAPI backend on port 8001..."
# Kill any previous uvicorn process
pkill -f "uvicorn api.app:app" || true
source venv/bin/activate
nohup python3 -m uvicorn api.app:app --host 0.0.0.0 --port 8001 --workers 2 > api.log 2>&1 &
echo "FastAPI PID: $!"

echo ""
echo "=========================================================="
echo " ThreatMapper is successfully deployed and running!"
echo " Web UI   : http://${EC2_IP}"
echo " API Docs : http://${EC2_IP}:8001/docs"
echo " Logs     : tail -f ${PROJECT_DIR}/api.log"
echo "=========================================================="
