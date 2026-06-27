#!/usr/bin/env bash
# SBOM-Shield installer
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Dependency checks ──────────────────────────────────────────────────────────

check_python() {
    local py
    py=$(command -v python3 2>/dev/null) || die "python3 not found. Install Python 3.10+."
    local ver
    ver=$("$py" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null)
    local major
    major=$("$py" -c 'import sys; print(sys.version_info.major)' 2>/dev/null)
    if [[ "$major" -lt 3 || ( "$major" -eq 3 && "$ver" -lt 10 ) ]]; then
        die "Python 3.10+ is required (found $("$py" --version 2>&1 | head -1))."
    fi
    success "Python $("$py" --version 2>&1 | awk '{print $2}') found"
}

check_node() {
    command -v node >/dev/null 2>&1 || die "Node.js not found. Install Node.js 20+ (https://nodejs.org)."
    local ver
    ver=$(node --version | sed 's/v//' | cut -d. -f1)
    if [[ "$ver" -lt 20 ]]; then
        die "Node.js 20+ is required (found $(node --version))."
    fi
    success "Node.js $(node --version) found"
}

check_npm() {
    command -v npm >/dev/null 2>&1 || die "npm not found. It ships with Node.js — reinstall Node."
    success "npm $(npm --version) found"
}

check_git() {
    if command -v git >/dev/null 2>&1; then
        success "git $(git --version | awk '{print $3}') found"
    else
        warn "git not found — build-manifest detection will be limited (optional)."
    fi
}

# ── cdxgen ─────────────────────────────────────────────────────────────────────

install_cdxgen() {
    if command -v cdxgen >/dev/null 2>&1; then
        success "cdxgen $(cdxgen --version 2>/dev/null | head -1) already installed"
        return
    fi
    info "Installing cdxgen globally via npm…"
    npm install -g @cyclonedx/cdxgen
    command -v cdxgen >/dev/null 2>&1 || die "cdxgen install failed — check npm permissions."
    success "cdxgen installed ($(cdxgen --version 2>/dev/null | head -1))"
}

# ── Syft ───────────────────────────────────────────────────────────────────────

install_syft() {
    if command -v syft >/dev/null 2>&1; then
        success "Syft $(syft version 2>/dev/null | grep Version | awk '{print $2}') already installed"
        return
    fi
    info "Installing Syft…"
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
        | sh -s -- -b /usr/local/bin 2>&1 \
        || { warn "Syft install failed. Run without it using --no-syft-fallback."; return; }
    success "Syft installed ($(syft version 2>/dev/null | grep Version | awk '{print $2}'))"
}

# ── Python venv + deps ─────────────────────────────────────────────────────────

setup_venv() {
    local venv="$REPO_DIR/.venv"
    if [[ -d "$venv" ]]; then
        info "Virtual environment already exists at .venv"
    else
        info "Creating Python virtual environment…"
        python3 -m venv "$venv"
        success "Virtual environment created"
    fi

    info "Installing Python dependencies…"
    "$venv/bin/pip" install --quiet --upgrade pip
    "$venv/bin/pip" install --quiet -r "$REPO_DIR/requirements.txt"
    success "Python dependencies installed"
}

# ── .env ──────────────────────────────────────────────────────────────────────

setup_env() {
    local env_file="$REPO_DIR/.env"
    local example="$REPO_DIR/.env.example"
    if [[ -f "$env_file" ]]; then
        info ".env already exists — skipping"
        return
    fi
    if [[ -f "$example" ]]; then
        cp "$example" "$env_file"
        success ".env created from .env.example"
    else
        cat > "$env_file" <<'EOF'
SBOMSHIELD_SECRET=sbomshield-dev-secret-change-in-prod
SBOMSHIELD_REPOS_DIR=~/repos
# VULDB_API_KEY=your-key-here
EOF
        success ".env created with defaults"
    fi
    warn "Review .env and change SBOMSHIELD_SECRET before any shared or production deployment."
}

# ── Database ───────────────────────────────────────────────────────────────────

setup_db() {
    info "Initialising database…"
    "$REPO_DIR/.venv/bin/python" "$REPO_DIR/storage/seed_db.py"
    success "Database ready at storage/scans.db"
    echo
    echo -e "  Default accounts:"
    echo -e "  ${BOLD}admin@sbom-shield.local${NC}  /  admin1234  (Admin)"
    echo -e "  ${BOLD}user@sbom-shield.local${NC}   /  user1234   (User)"
    warn "Change these credentials before sharing access."
}

# ── Summary ────────────────────────────────────────────────────────────────────

print_summary() {
    echo
    echo -e "${BOLD}${GREEN}Installation complete.${NC}"
    echo
    echo -e "  Activate the virtual environment:"
    echo -e "  ${CYAN}source .venv/bin/activate${NC}"
    echo
    echo -e "  Run a scan:"
    echo -e "  ${CYAN}python main.py /path/to/project${NC}"
    echo
    echo -e "  Start the dashboard:"
    echo -e "  ${CYAN}uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload${NC}"
    echo -e "  Then open ${CYAN}http://localhost:8000${NC}"
    echo
}

# ── Main ───────────────────────────────────────────────────────────────────────

main() {
    echo -e "${BOLD}SBOM-Shield Installer${NC}"
    echo "────────────────────────────────────────"

    SKIP_SYFT=false
    SKIP_DB=false
    for arg in "$@"; do
        case "$arg" in
            --no-syft)    SKIP_SYFT=true ;;
            --no-seed-db) SKIP_DB=true ;;
            --help|-h)
                echo "Usage: ./install.sh [--no-syft] [--no-seed-db]"
                echo
                echo "  --no-syft      Skip Syft installation (use --no-syft-fallback at scan time)"
                echo "  --no-seed-db   Skip database initialisation"
                exit 0
                ;;
        esac
    done

    check_python
    check_node
    check_npm
    check_git

    install_cdxgen
    $SKIP_SYFT || install_syft

    setup_venv
    setup_env
    $SKIP_DB || setup_db

    print_summary
}

main "$@"
