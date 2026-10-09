# SFYNX — Hybrid Security Testing Platform

> "Let deterministic security tools find the problems. Let the LLM understand the problems."

SFYNX is a hybrid security testing platform designed to test web applications, APIs,
cloud-facing attack surfaces, AI agents, RAG systems, and AI memory systems.

## Architecture

Traditional security tools perform high-volume deterministic scanning.
An LLM is used **only** at the final triage/reasoning stage to correlate findings,
reduce false positives, prioritize risks, and generate human-readable reports.

## Current Phase: Phase 1 — Basic Scanner MVP

- FastAPI backend with scan endpoint
- Authorization & Scope Gate
- httpx runner (target discovery)
- Nuclei runner (vulnerability scanning)
- Common findings schema
- JSON output

## Quick Start

```bash
# 1. Set up Python environment
cd sfynx/backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Copy env file
cp .env.example .env

# 3. Run the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 4. Run tests
pytest tests/ -v
```

## API Usage

```bash
# Submit a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "authorization": true,
    "scope": ["localhost:3000"]
  }'

# Check scan status
curl http://localhost:8000/api/v1/scans/{scan_id}

# Get scan findings
curl http://localhost:8000/api/v1/scans/{scan_id}/findings
```

## Project Structure

```
sfynx/
├── backend/
│   ├── app/
│   │   ├── api/          # FastAPI route handlers
│   │   ├── core/         # Config, authorization, security
│   │   ├── schemas/      # Pydantic models
│   │   ├── services/     # Business logic
│   │   ├── runners/      # Security tool adapters
│   │   ├── normalizer/   # Output normalization
│   │   └── main.py       # Application entry point
│   └── tests/            # pytest test suite
├── docker/               # Dockerfiles (Phase 3)
├── docs/                 # Documentation
├── .env.example
└── README.md
```

## Security

- All scans require explicit authorization
- Target scope validation before any scanning
- Only safe/local targets in MVP (localhost, 127.0.0.1)
- No arbitrary shell execution — subprocess argument arrays only
- All secrets via environment variables

## License

MIT
