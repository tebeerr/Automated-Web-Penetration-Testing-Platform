SHELL := /bin/sh

.PHONY: help install backend frontend front-install api-install api-fmt api-lint api-test clean

help:
	@echo "Sentinel — make targets"
	@echo "  install        Install backend + frontend deps"
	@echo "  api-install    Install backend deps only (pip install -e .)"
	@echo "  front-install  Install frontend deps only (npm install)"
	@echo "  backend        Run FastAPI dev server (uvicorn --reload)"
	@echo "  frontend       Run Vite dev server"
	@echo "  api-fmt        ruff format the backend"
	@echo "  api-lint       ruff check the backend"
	@echo "  api-test       Run backend tests"
	@echo "  clean          Remove SQLite DB + generated reports"

install: api-install front-install

api-install:
	cd apps/backend && python -m pip install -U pip && pip install -e .[dev]

front-install:
	cd apps/frontend && npm install --no-audit --no-fund

backend:
	cd apps/backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

frontend:
	cd apps/frontend && npm run dev

api-fmt:
	cd apps/backend && ruff format app

api-lint:
	cd apps/backend && ruff check app

api-test:
	cd apps/backend && pytest -q

clean:
	rm -f apps/backend/sentinel.db
	rm -rf apps/backend/reports
