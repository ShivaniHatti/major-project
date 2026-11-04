# SentinelX Starter

Starter skeleton for SentinelX: Evidence-Aware Autonomous Cyber Investigation and AI-Agent Security Platform.

## Requirements
Python 3.10+, Node.js LTS, VS Code.

## Start backend (Windows PowerShell)
```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Backend health: http://127.0.0.1:5000/api/health

## Start frontend (second terminal)
```powershell
cd frontend
npm install
npm run dev
```
Open the local URL printed by Vite (normally http://localhost:5173).

This is a development scaffold. Advanced collection, ML detection, hypothesis-driven investigation, NBE, evidence sufficiency and agent monitoring are TODO modules, not implemented features. Use synthetic or authorized logs only.
