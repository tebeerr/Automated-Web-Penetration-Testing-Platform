SHELL := /bin/sh
COMPOSE := docker compose -f infra/docker-compose.yml --env-file .env
COMPOSE_DEV := $(COMPOSE) -f infra/docker-compose.dev.yml

.PHONY: help up down restart logs ps build dev dev-down backend-shell worker-shell \
        front-install front-dev front-build api-fmt api-lint api-test clean

help:
	@echo "Sentinel — make targets"
	@echo "  up            Bring up the full stack (prod-ish)"
	@echo "  down          Tear down the stack (keeps volumes)"
	@echo "  dev           Bring up the stack with live-reload mounts"
	@echo "  dev-down      Tear down the dev stack"
	@echo "  logs          Tail logs for all services"
	@echo "  build         Rebuild all images"
	@echo "  front-install Install frontend deps (host)"
	@echo "  front-dev     Run Vite dev server on host"
	@echo "  front-build   Build the frontend bundle"
	@echo "  api-fmt       ruff format the backend"
	@echo "  api-lint      ruff check the backend"
	@echo "  api-test      Run backend tests"

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

restart: down up

logs:
	$(COMPOSE) logs -f --tail=200

ps:
	$(COMPOSE) ps

build:
	$(COMPOSE) build

dev:
	$(COMPOSE_DEV) up

dev-down:
	$(COMPOSE_DEV) down

backend-shell:
	$(COMPOSE) exec backend /bin/bash

worker-shell:
	$(COMPOSE) exec worker /bin/bash

front-install:
	cd apps/frontend && npm install

front-dev:
	cd apps/frontend && npm run dev

front-build:
	cd apps/frontend && npm run build

api-fmt:
	cd apps/backend && ruff format app

api-lint:
	cd apps/backend && ruff check app

api-test:
	cd apps/backend && pytest -q

clean:
	$(COMPOSE) down -v
