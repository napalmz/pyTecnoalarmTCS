#!/usr/bin/env bash
set -e

VENV=".venv"
PYTHON=${PYTHON:-python3}

echo "[setup] Checking Python..."
command -v $PYTHON >/dev/null 2>&1 || {
  echo "Python3 not found"; exit 1;
}

# 1) Create venv if missing
if [ ! -d "$VENV" ]; then
  echo "[setup] Creating virtual environment in $VENV"
  $PYTHON -m venv $VENV
else
  echo "[setup] Virtual environment already exists"
fi

# 2) Activate venv
source "$VENV/bin/activate"

# 3) Upgrade core tooling
echo "[setup] Upgrading pip/setuptools/wheel"
pip install --upgrade pip setuptools wheel dotenv

# 4) Install requirements
if [ -f requirements.txt ]; then
  echo "[setup] Installing requirements"
  pip install -r requirements.txt
  pip install -e .
else
  echo "requirements.txt not found, fallback locale only install"
  pip install -e .
fi

echo
echo "[setup] Environment ready."
echo "To activate later run:"
echo "source $VENV/bin/activate"