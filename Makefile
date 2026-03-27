.PHONY: reload up down build logs

# Rebuild web image, restart, then stream logs — run after any code change
reload:
	docker compose build web
	docker compose up -d
	docker compose logs -f web --tail=80

# Start all services (no rebuild)
up:
	docker compose up -d

# Stop all services
down:
	docker compose down

# Build image only (no restart)
build:
	docker compose build web

# Stream live web logs
logs:
	docker compose logs -f web --tail=100
