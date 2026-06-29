#!/bin/bash
# ─────────────────────────────────────────────────────────
# Sentinel Pentest Hub — Kali Linux VM Setup Script
# Run this ONCE on a fresh Kali VM before starting Sentinel
# ─────────────────────────────────────────────────────────
set -e

echo "[*] Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo "[*] Installing system dependencies..."
sudo apt install -y \
    python3.11 python3.11-venv python3-pip \
    nodejs npm \
    nmap \
    metasploit-framework \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
    libcairo2 libffi-dev libglib2.0-0 \
    postgresql postgresql-client

echo "[*] Starting PostgreSQL for Metasploit..."
sudo systemctl enable postgresql
sudo systemctl start postgresql

echo "[*] Initializing Metasploit database..."
sudo msfdb init

echo "[*] Starting msfrpcd (Metasploit RPC daemon)..."
# Start msfrpcd in background with Sentinel's default password
msfrpcd -P sentinel_msf -S -a 127.0.0.1 -p 55553 &
echo "[*] msfrpcd started on 127.0.0.1:55553"

echo "[*] Cloning Sentinel repository..."
cd ~/Desktop
git clone https://github.com/tebeerr/Automated-Web-Penetration-Testing-Platform.git
cd Automated-Web-Penetration-Testing-Platform

echo "[*] Setting up backend..."
cd apps/backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pip install python-nmap pymetasploit3

echo "[*] Copying environment file..."
cp ../../.env.example .env

# Inject Kali-specific overrides
cat >> .env << 'KALI_OVERRIDES'

# ── Kali VM Pipeline Settings ────────────────────
PIPELINE_MODE=full_pipeline
NMAP_PATH=/usr/bin/nmap
NMAP_SCAN_ARGS=-sV -sC --top-ports 1000 -T4
NMAP_VULN_ARGS=--script vuln
NMAP_OS_DETECTION=true
MSF_RPC_HOST=127.0.0.1
MSF_RPC_PORT=55553
MSF_RPC_PASSWORD=sentinel_msf
MSF_RPC_SSL=false
MSF_WORKSPACE=sentinel
MSF_EXPLOIT_ENABLED=true
MSF_SAFE_EXPLOITS_ONLY=true
POST_EXPLOIT_ENABLED=true
KALI_OVERRIDES

echo "[*] Setting up frontend..."
cd ../frontend
npm install

echo ""
echo "─────────────────────────────────────────────────"
echo " Sentinel Pentest Hub — Kali Setup Complete!"
echo "─────────────────────────────────────────────────"
echo ""
echo " Start backend:  cd apps/backend && source .venv/bin/activate && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
echo " Start frontend: cd apps/frontend && npm run dev"
echo " msfrpcd status: curl -k https://127.0.0.1:55553"
echo ""
echo " ⚠️  IMPORTANT: Only scan targets you own or have authorization for!"
echo "─────────────────────────────────────────────────"
