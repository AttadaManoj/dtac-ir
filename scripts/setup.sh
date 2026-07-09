#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  DTAC-IR Development Environment Setup — WSL2 / Ubuntu                 ║
# ║  Run once after cloning the repo.                                       ║
# ║  Usage: chmod +x scripts/setup.sh && ./scripts/setup.sh                ║
# ╚══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Python Version Check ───────────────────────────────────────────────────────
PYTHON_VERSION=$(python3 -c "import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")")
PYTHON_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 11 ]); then
  error "Python 3.11+ required. Found: $PYTHON_VERSION. Install with: sudo apt install python3.11"
fi
info "Python version: $PYTHON_VERSION ✓"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   DTAC-IR: Dev Environment Setup             ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── 1. System Packages ─────────────────────────────────────────────────────────
info "Updating system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
  build-essential \
  libpcap-dev \
  libpq-dev \
  python3-pip \
  python3-venv \
  curl \
  git \
  net-tools \
  iproute2 \
  postgresql-client

success "System packages installed"

# ── 2. Node.js (via nvm) ───────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  info "Installing Node.js 20 via nvm..."
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
  export NVM_DIR="$HOME/.nvm"
  source "$NVM_DIR/nvm.sh"
  nvm install 20
  nvm use 20
  nvm alias default 20
  success "Node.js $(node --version) installed"
else
  success "Node.js already installed: $(node --version)"
fi

# ── 3. Docker ──────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  info "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER"
  warn "Docker installed. You may need to log out and back in for group changes."
else
  success "Docker already installed: $(docker --version)"
fi

# ── 4. Python Virtual Environment ─────────────────────────────────────────────
info "Setting up Python virtual environment..."
cd "$(dirname "$0")/.."  # Move to project root

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip -q
pip install -r backend/requirements.txt -q
  echo "  (ML training deps are separate: pip install -r ml/requirements-train.txt)"

success "Python venv ready: $(python --version)"

# ── 5. Environment File ────────────────────────────────────────────────────────
if [ ! -f .env ]; then
  info "Creating .env from template..."
  cp .env.example .env
  # Generate a random secret key
  SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  sed -i "s/your-super-secret-key-change-this-in-production-min-32-chars/$SECRET/" .env
  success ".env created with generated secret key"
else
  warn ".env already exists — skipping"
fi

# ── 6. Frontend Dependencies ───────────────────────────────────────────────────
if command -v npm &>/dev/null; then
  info "Installing frontend dependencies..."
  cd frontend && npm install -q && cd ..
  success "Frontend dependencies installed"
else
  warn "npm not found — install Node.js first, then run: cd frontend && npm install"
fi

# ── 7. Create log directory ────────────────────────────────────────────────────
mkdir -p backend/logs ml/models
success "Log and model directories created"

# ── 8. Network Interface Detection ────────────────────────────────────────────
info "Detecting network interface..."
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -n "$IFACE" ]; then
  sed -i "s/CAPTURE_INTERFACE=eth0/CAPTURE_INTERFACE=$IFACE/" .env
  success "Set capture interface to: $IFACE"
else
  warn "Could not detect interface — defaulting to eth0 in .env"
fi

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅  Setup Complete!                                         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║  Next steps:                                                 ║"
echo "║  1. Start DB:     cd docker && docker compose up -d postgres ║"
echo "║  2. Start API:    source .venv/bin/activate                  ║"
echo "║                   cd backend && uvicorn app.main:app --reload║"
echo "║  3. Start UI:     cd frontend && npm run dev                 ║"
echo "║  4. API Docs:     http://localhost:8000/api/docs             ║"
echo "║                                                              ║"
echo "║  ⚠️  Packet capture requires sudo on WSL2                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
