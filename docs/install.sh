#!/usr/bin/env bash
# install.sh - set up zsazsa for the first time
#
# What this script does:
#   1. Checks for Python 3.10+ and pip
#   2. Creates a Python virtual environment in ./venv
#   3. Installs all dependencies from requirements.txt
#   4. Creates the data/ directory
#   5. Writes a minimal config/__init__.py (if not already present)
#   6. Optionally generates a self-signed SSL certificate
#
# Usage (run from the project root, not from docs/):
#   bash docs/install.sh
#
# After running:
#   1. Edit config/__init__.py and fill in your MISP_URL, MISP_KEY, etc.
#   2. Start the application: source venv/bin/activate && python run_webapp.py
#   3. (Optional) install as a service: see docs/zsazsa.service.template

set -euo pipefail

PYTHON="${PYTHON:-python3}"
VENV_DIR="venv"
CONFIG_FILE="config/__init__.py"
CONFIG_EXAMPLE="config/__init__.py.example"
DATA_DIR="data"

echo "============================================================"
echo " zsazsa installer"
echo "============================================================"
echo ""

# ── 1. Python version check ────────────────────────────────────────────────────

if ! command -v "$PYTHON" &>/dev/null; then
    echo "ERROR: Python 3 not found. Install Python 3.10 or later and re-run."
    exit 1
fi

PYTHON_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$("$PYTHON" -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$("$PYTHON" -c "import sys; print(sys.version_info.minor)")

if [[ "$PYTHON_MAJOR" -lt 3 ]] || { [[ "$PYTHON_MAJOR" -eq 3 ]] && [[ "$PYTHON_MINOR" -lt 10 ]]; }; then
    echo "ERROR: Python 3.10 or later is required (found $PYTHON_VERSION)."
    exit 1
fi

echo "Python $PYTHON_VERSION found."

# ── 2. Create virtual environment ─────────────────────────────────────────────

if [[ -d "$VENV_DIR" ]]; then
    echo "Virtual environment already exists at ./$VENV_DIR - skipping creation."
else
    echo "Creating virtual environment in ./$VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

PIP="$VENV_DIR/bin/pip"

# ── 3. Install dependencies ───────────────────────────────────────────────────

echo "Installing dependencies from requirements.txt ..."
"$PIP" install --upgrade pip --quiet
"$PIP" install -r requirements.txt --quiet
echo "Dependencies installed."

# ── 4. Create data directory ──────────────────────────────────────────────────

if [[ ! -d "$DATA_DIR" ]]; then
    mkdir -p "$DATA_DIR"
    echo "Created $DATA_DIR/ directory."
fi

# ── 5. Create initial config/__init__.py ──────────────────────────────────────

mkdir -p config

if [[ -f "$CONFIG_FILE" ]]; then
    echo "config/__init__.py already exists - skipping."
else
    if [[ -f "$CONFIG_EXAMPLE" ]]; then
        cp "$CONFIG_EXAMPLE" "$CONFIG_FILE"
        echo "Copied config/__init__.py.example to config/__init__.py."
    else
        # Generate a random SECRET_KEY and write a minimal config/__init__.py
        SECRET_KEY=$("$VENV_DIR/bin/python" -c "import secrets; print(secrets.token_hex(32))")
        cat > "$CONFIG_FILE" <<EOF
SECRET_KEY = "$SECRET_KEY"

# MISP - scraper / analyser pipeline
MISP_URL = 'https://your-misp-instance.example.com'
MISP_KEY = 'your-misp-api-key-here'
MISP_VERIFYCERT = False

# MISP - webapp (CTI program objects: stakeholders, PIRs, GIRs)
# Defaults to the same server; override to use a dedicated MISP instance.
MISP_WEBAPP_URL = 'https://your-misp-instance.example.com'
MISP_WEBAPP_KEY = 'your-misp-api-key-here'
MISP_WEBAPP_VERIFYCERT = False

# Anthropic
ANTHROPIC_API_KEY = 'sk-ant-your-key-here'
ANTHROPIC_MODEL = 'claude-sonnet-4-6'

# Mattermost (leave empty to disable notifications)
MATTERMOST_WEBHOOK_URL = ''

# Additional MISP servers queried by the data-collection page.
MISP_SERVERS = []

# Collection sources offered when editing a PIR or GIR.
# Derived automatically from the MISP scraper and configured MISP servers.
def _build_collection_sources():
    items = ['misp-scraper']
    for s in MISP_SERVERS:
        label = (s.get('label') or '').strip()
        if label and label not in items:
            items.append(label)
    return items

COLLECTION_SOURCES = _build_collection_sources()

# Product types used for stakeholder subscriptions and PIR deliverables
PRODUCT_TYPES = [
    'Flash intel alert',
    'Vulnerability exploitation advisory',
    'Threat actor profile',
    'Campaign profile',
    'Indicator feed',
    'Daily threat briefing',
    'Detection engineering request',
    'Threat landscape report',
    'Incident response support',
    'Hunt support',
]

# MISP context tags - entity type markers
TAG_STAKEHOLDER = 'zsazsa:type="stakeholder"'
TAG_PIR         = 'zsazsa:type="pir"'
TAG_GIR         = 'zsazsa:type="gir"'
TAG_RFI         = 'zsazsa:type="rfi"'

# MISP context tags - product classification
TAG_FLASH_INTEL = 'zsazsa:ctiproduct="flash-intel"'
TAG_VEA         = 'zsazsa:ctiproduct="vea"'
TAG_BRIEFING    = 'zsazsa:ctiproduct="daily-briefing"'

# Analyser
POLL_WINDOW_HOURS = 24
SCRAPER_MARKER_TAG = 'zsazsa:source="misp-scraper"'

# Paths
FOCUS_POINTS_FILE = 'focus_points.json'
STATE_FILE = 'data/state.json'
DB_FILE = 'data/analyser.db'

# Logging
LOG_FILE = 'data/analyser.log'
LOG_LEVEL = 'INFO'

# Web server
HOSTNAME = '0.0.0.0'
PORT = 5000
SSL_ENABLED = False
SSL_CERT = 'certs/zsazsa.crt'
SSL_KEY = 'certs/zsazsa.key'
EOF
        echo "Created config/__init__.py with a generated SECRET_KEY."
        echo ""
        echo "  >>> ACTION REQUIRED: edit config/__init__.py and fill in your MISP_URL,"
        echo "      MISP_KEY, and ANTHROPIC_API_KEY before starting the application."
        echo ""
    fi
fi

# ── 6. Optional: SSL certificate ──────────────────────────────────────────────

echo ""
read -r -p "Generate a self-signed SSL certificate for zsazsa.demo.cudeso.be? [y/N] " ssl_answer
if [[ "${ssl_answer,,}" == "y" ]]; then
    read -r -p "Hostname for the certificate [zsazsa.demo.cudeso.be]: " ssl_hostname
    ssl_hostname="${ssl_hostname:-zsazsa.demo.cudeso.be}"
    if command -v openssl &>/dev/null; then
        bash docs/create_cert.sh "$ssl_hostname"
    else
        echo "WARNING: openssl not found - skipping certificate generation."
        echo "  Install openssl and run:  bash docs/create_cert.sh $ssl_hostname"
    fi
else
    echo "Skipping SSL certificate generation."
fi

# ── Done ───────────────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo " Installation complete"
echo "============================================================"
echo ""
echo "To start zsazsa:"
echo "  source $VENV_DIR/bin/activate"
echo "  python run_webapp.py"
echo ""
echo "Or with the venv path explicit (no activation needed):"
echo "  $VENV_DIR/bin/python run_webapp.py"
echo ""
echo "To install as a systemd service, see: zsazsa.service.template"
echo ""
