# PatchMind
AI-powered multi-agent vulnerability remediation platform.
## Setup
cp .env.example .env
pip install -r requirements.txt
## Run
python -m uvicorn api.server:app --reload
