#!/usr/bin/env bash
# CyberMint Installer
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔══════════════════════════════╗"
echo "  ║       CYBERMINT INSTALL      ║"
echo "  ║  Cybersecurity Command Hub   ║"
echo "  ╚══════════════════════════════╝"
echo -e "${NC}"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}Error: Python 3 is required.${NC}"
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${CYAN}[*]${NC} Python $PY_VER detected."

# Install dependencies
echo -e "${CYAN}[*]${NC} Installing dependencies..."
pip3 install -r requirements.txt --quiet

# Create directories
echo -e "${CYAN}[*]${NC} Creating directories..."
mkdir -p database/logs reports plugins themes docs

# Make main.py executable
chmod +x main.py

# Create cybermint launcher
echo -e "${CYAN}[*]${NC} Creating launcher..."
cat > cybermint << 'EOF'
#!/usr/bin/env bash
cd "$(dirname "$(realpath "$0")")"
python3 main.py "$@"
EOF
chmod +x cybermint

echo -e "${GREEN}"
echo "  ╔══════════════════════════════╗"
echo "  ║    Installation Complete!    ║"
echo "  ╚══════════════════════════════╝"
echo -e "${NC}"
echo "  Run with:  python3 main.py"
echo "          or ./cybermint"
echo ""
