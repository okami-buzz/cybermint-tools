#!/usr/bin/env bash
# CyberMint Installer — works on Linux, macOS, and Termux (Android)
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔══════════════════════════════╗"
echo "  ║       CYBERMINT INSTALL      ║"
echo "  ║  Cybersecurity Command Hub   ║"
echo "  ╚══════════════════════════════╝"
echo -e "${NC}"

# ── Detect environment ───────────────────────────────────────────────────────
IS_TERMUX=false
if [ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ]; then
    IS_TERMUX=true
    echo -e "${YELLOW}[!]${NC} Termux environment detected."
fi

# ── Check Python ─────────────────────────────────────────────────────────────
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}[✗] Python 3 is required. Install it first:${NC}"
    if $IS_TERMUX; then
        echo "    pkg install python"
    fi
    exit 1
fi

PY_VER=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${CYAN}[*]${NC} Python $PY_VER detected."

# ── Check pip ────────────────────────────────────────────────────────────────
if ! $PYTHON -m pip --version &>/dev/null; then
    echo -e "${RED}[✗] pip not found.${NC}"
    if $IS_TERMUX; then
        echo "    Run: pkg install python && pip install --upgrade pip"
    fi
    exit 1
fi

# ── Install dependencies ─────────────────────────────────────────────────────
echo -e "${CYAN}[*]${NC} Installing dependencies..."

if $IS_TERMUX; then
    # On Termux, install packages one by one to skip any that fail
    PACKAGES=(rich requests dnspython python-whois colorama pyfiglet prompt_toolkit tabulate)
    for pkg in "${PACKAGES[@]}"; do
        echo -e "    Installing ${pkg}..."
        $PYTHON -m pip install "$pkg" --quiet 2>/dev/null \
            && echo -e "    ${GREEN}✓${NC} $pkg" \
            || echo -e "    ${YELLOW}⚠${NC} $pkg skipped (optional)"
    done
else
    $PYTHON -m pip install -r requirements.txt --quiet
fi

# ── Create directories ────────────────────────────────────────────────────────
echo -e "${CYAN}[*]${NC} Creating directories..."
mkdir -p database/logs reports plugins themes docs

# ── Make scripts executable ──────────────────────────────────────────────────
chmod +x main.py 2>/dev/null || true

# ── Create launcher ──────────────────────────────────────────────────────────
echo -e "${CYAN}[*]${NC} Creating launcher..."
cat > cybermint << EOF
#!/usr/bin/env bash
cd "\$(dirname "\$(realpath "\$0")")"
${PYTHON} main.py "\$@"
EOF
chmod +x cybermint

echo -e "${GREEN}"
echo "  ╔══════════════════════════════╗"
echo "  ║    Installation Complete!    ║"
echo "  ╚══════════════════════════════╝"
echo -e "${NC}"
echo "  Run with:  ${PYTHON} main.py"
echo "          or ./cybermint"
echo ""
