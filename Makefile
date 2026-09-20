# Convenience targets. PYTHONPATH=src makes every target work without an editable install.
PY ?= python3.12
VENV ?= .venv
BIN := $(VENV)/bin
RUN := PYTHONPATH=src $(BIN)

.PHONY: install api dashboard seed test lint format check docker-build docker-up docker-down clean

install:                      ## create the virtualenv and install dependencies
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

api:                          ## API on :8000  (Swagger UI at /docs)
	$(RUN)/uvicorn sentinelguard.api.app:create_app --factory --host 127.0.0.1 --port 8000

dashboard:                    ## Streamlit dashboard on :8501 (needs the API running)
	SENTINELGUARD_API_BASE_URL=http://127.0.0.1:8000 $(RUN)/streamlit run src/sentinelguard/dashboard/app.py --server.port 8501

seed:                         ## scan all bundled samples through the running API
	$(RUN)/python scripts/seed_demo.py http://127.0.0.1:8000

test:                         ## full test suite
	$(RUN)/pytest

lint:
	$(BIN)/ruff check src tests scripts

format:
	$(BIN)/ruff format src tests scripts

check: lint test              ## what CI runs

docker-build:
	docker build -t sentinelguard-ai:local .

docker-up:                    ## API :8000 + dashboard :8501
	docker compose up --build

docker-down:
	docker compose down

clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov data
