# DTAC-IR Makefile — Common dev commands
# Usage: make <target>

.PHONY: help setup dev-backend dev-frontend dev db-up db-down test lint clean

VENV=.venv/bin/activate
PYTHON=source $(VENV) && python

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup:  ## Run full dev environment setup
	bash scripts/setup.sh

db-up:  ## Start PostgreSQL + Redis via Docker
	cd docker && docker compose up -d postgres redis
	@echo "⏳ Waiting for Postgres..."
	@sleep 3
	@echo "✅ Database ready"

db-down:  ## Stop all Docker services
	cd docker && docker compose down

dev-backend:  ## Start FastAPI backend with hot-reload
	source $(VENV) && cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dev-frontend:  ## Start React dev server
	cd frontend && npm run dev

dev:  ## Start everything (DB + backend + frontend) — needs tmux or run in 3 terminals
	@echo "Run these in separate terminals:"
	@echo "  Terminal 1: make db-up"
	@echo "  Terminal 2: make dev-backend"
	@echo "  Terminal 3: make dev-frontend"

test:  ## Run all backend tests
	source $(VENV) && cd backend && pytest tests/ -v --tb=short

test-engine:  ## Test detection engine in simulation mode
	source $(VENV) && cd backend && python -c "
from app.detection.engine import DetectionEngine
import time

alerts = []
engine = DetectionEngine(alert_callback=lambda f: alerts.append(f))
engine._simulate_traffic()
engine._running = True
time.sleep(5)
engine.stop_capture()
print(f'Stats: {engine.get_stats()}')
print(f'Alerts captured: {len(alerts)}')
"

lint:  ## Run linting
	source $(VENV) && cd backend && python -m flake8 app/ --max-line-length=100
	cd frontend && npm run lint

clean:  ## Remove generated files
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .venv backend/logs/*.log

docker-build:  ## Build all Docker images
	cd docker && docker compose build

docker-up:  ## Start full stack via Docker
	cd docker && docker compose up -d

docker-logs:  ## Tail all service logs
	cd docker && docker compose logs -f

# ── ML Targets ────────────────────────────────────────────────────────────────

ml-synthetic:  ## Generate synthetic dataset for testing (no CICIDS2017 needed)
	source $(VENV) && pip install -r ml/requirements-train.txt -q
	source $(VENV) && python ml/generate_synthetic.py --samples 100000
	@echo "✅ Synthetic dataset ready at ml/datasets/synthetic.csv"

ml-train-fast:  ## Train model on synthetic data (fast — ~2 min)
	source $(VENV) && pip install -r ml/requirements-train.txt -q
	source $(VENV) && python ml/train.py --fast --dataset-dir ml/datasets/
	@echo "✅ Model ready at ml/models/"

ml-train:  ## Train model — production quality (~15 min on CICIDS2017)
	source $(VENV) && pip install -r ml/requirements-train.txt -q
	source $(VENV) && python ml/train.py --dataset-dir ml/datasets/

ml-status:  ## Check model status via API
	curl -s http://localhost:8000/api/v1/ml/status | python3 -m json.tool

ml-predict:  ## Test model with a sample port scan packet (API must be running)
	curl -s -X POST http://localhost:8000/api/v1/ml/predict \
	  -H "Content-Type: application/json" \
	  -d '{"destination_port": 22, "syn_flag_count": 1, "rst_flag_count": 1, "flow_packets_per_sec": 500}' \
	  | python3 -m json.tool

ml-full-pipeline:  ## Run synthetic gen + fast train + verify in one command
	make ml-synthetic && make ml-train-fast
	@echo ""
	@echo "✅ Full ML pipeline complete. Start backend and run: make ml-status"
