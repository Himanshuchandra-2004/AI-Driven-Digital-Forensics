#!/usr/bin/env bash
# ============================================================
# AI-Driven Digital Forensics — Local Setup Script
# ============================================================
# Sets up the entire project for local development:
#   1. Installs backend Python dependencies
#   2. Trains ML models on synthetic demo data
#   3. Initializes database and seeds default users
#   4. Installs frontend npm dependencies
#   5. Prints start instructions
#
# Usage:
#   cd "Digital Forensics"
#   chmod +x scripts/setup_local.sh
#   ./scripts/setup_local.sh
# ============================================================

set -e

echo ""
echo "============================================================"
echo "  AI-Driven Digital Forensics — Local Setup"
echo "============================================================"
echo ""

# Navigate to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"
echo "Project directory: $PROJECT_DIR"
echo ""

# ---- Step 1: Backend dependencies ----
echo "--- Step 1/5: Installing backend dependencies ---"
cd "$PROJECT_DIR/backend"
pip3 install -r requirements.txt --quiet
echo "✓ Backend dependencies installed"
echo ""

# ---- Step 2: Train ML models ----
echo "--- Step 2/5: Training ML models on synthetic data ---"
cd "$PROJECT_DIR"
python3 -m scripts.train_on_demo
echo "✓ ML models trained"
echo ""

# ---- Step 3: Initialize database ----
echo "--- Step 3/5: Initializing database ---"
cd "$PROJECT_DIR"
python3 -m scripts.init_db
echo "✓ Database initialized"
echo ""

# ---- Step 4: Frontend dependencies ----
echo "--- Step 4/5: Installing frontend dependencies ---"
cd "$PROJECT_DIR/frontend"
npm install --silent
echo "✓ Frontend dependencies installed"
echo ""

# ---- Step 5: Done! ----
echo "--- Step 5/5: Setup complete! ---"
echo ""
echo "============================================================"
echo "  Setup Complete! Start the application:"
echo "============================================================"
echo ""
echo "  Terminal 1 (Backend):"
echo "    cd backend && uvicorn app.main:app --reload --port 8000"
echo ""
echo "  Terminal 2 (Frontend):"
echo "    cd frontend && npm run dev"
echo ""
echo "  Then open: http://localhost:5173"
echo ""
echo "  Default login:"
echo "    admin / admin123"
echo "    investigator / invest123"
echo ""
echo "  API docs: http://localhost:8000/docs"
echo "============================================================"
echo ""
