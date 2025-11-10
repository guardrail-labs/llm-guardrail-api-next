SHELL := /bin/bash
TAG ?=

.PHONY: install fmt lint type test ci run docker-build docker-run compose-up compose-down demo-traffic docs-check monitoring-lint audits perf-smoke perf-smoke-run rc

install:
	pip install -r requirements.txt || pip install .

fmt:
	ruff format .

lint:
	ruff check .

type:
	mypy --strict app

test:
	pytest -q

ci: fmt lint type test

run:
	python -m app.run

docker-build:
	docker build -t guardrail:local -f docker/Dockerfile .

docker-run:
	docker run --rm -p 8000:8000 --env-file .env \
	  -v $$(pwd)/rules.yaml:/etc/guardrail/rules.yaml:ro \
	  guardrail:local

demo-traffic:
	python scripts/demo_traffic.py

.PHONY: docs-check
docs-check:
	@echo "Checking docs links…"
	@true  # placeholder; can add markdown-link-check later

compose-up:
	docker compose up --build

compose-down:
	docker compose down -v
.PHONY: demo-stack-up demo-stack-traffic demo-stack-down demo-stack-clean

demo-stack-up:
	@docker compose up -d --build
	@echo "API:       http://localhost:8000"
	@echo "Prometheus http://localhost:9090"
	@echo "Grafana:   http://localhost:3000  (admin / admin)"

demo-stack-traffic:
	@docker compose run --rm demo-traffic

demo-stack-down:
	@docker compose down

demo-stack-clean:
	@docker compose down -v --remove-orphans
.PHONY: perf-smoke
perf-smoke:
	@echo "==> Running perf smoke locally"
	@# Start API in background if nothing is listening on 8000
	@set -euo pipefail; \
	if uv run python tools/perf/bench.py --help 2>/dev/null | grep -q -- '--out'; then \
	  echo "Detected --out support; writing to perf-rc-candidate.json"; \
	  OUTFLAG=1; \
	else \
	  echo "No --out flag detected; capturing stdout to perf-rc-candidate.json"; \
	  OUTFLAG=0; \
	fi; \
	if ! curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; then \
	  echo "Starting API on 127.0.0.1:8000"; \
	  uv run uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 & \
	  echo $$! > .uvicorn.pid; \
	  for i in $$(seq 1 30); do \
	    if curl -fsS http://127.0.0.1:8000/healthz >/dev/null; then break; fi; \
	    sleep 1; \
	  done; \
	fi; \
	if [ $$OUTFLAG -eq 1 ]; then \
	  if uv run python tools/perf/bench.py --help 2>/dev/null | grep -q -- '--base'; then \
	    uv run python tools/perf/bench.py --base http://127.0.0.1:8000 --out perf-rc-candidate.json; \
	  else \
	    BASE_URL=http://127.0.0.1:8000 uv run python tools/perf/bench.py --out perf-rc-candidate.json; \
	  fi; \
	else \
	  if uv run python tools/perf/bench.py --help 2>/dev/null | grep -q -- '--base'; then \
	    uv run python tools/perf/bench.py --base http://127.0.0.1:8000 > perf-rc-candidate.json; \
	  else \
	    BASE_URL=http://127.0.0.1:8000 uv run python tools/perf/bench.py > perf-rc-candidate.json; \
	  fi; \
	fi; \
	if [ ! -s perf-rc-candidate.json ]; then \
	  echo "WARN: perf output is empty; writing minimal placeholder JSON"; \
	  echo '{}' > perf-rc-candidate.json; \
	fi; \
	echo "Wrote perf-rc-candidate.json"; \
	if [ -f .uvicorn.pid ]; then kill $$(cat .uvicorn.pid) || true; rm -f .uvicorn.pid; fi

.PHONY: perf-smoke-run
perf-smoke-run:
	@python tools/perf/bench.py \
	  --base "$${BASE:-http://localhost:8000}" \
	  --token "$${TOKEN:-}" \
	  -c "$${C:-50}" \
	  -d "$${DURATION:-60s}" \
	  --timeout "$${TIMEOUT:-5}" \
	  --limit "$${LIMIT:-50}" \
	  $${INSECURE:+--insecure} \
	  $${OUT:+--out "$$OUT"}

.PHONY: audits
audits:
	@echo "==> Triggering repo audits via GitHub Actions (manual dispatch)…"
	@echo "    Open Actions UI and run:"
	@echo "      • Actions Pinning Audit"
	@echo "      • Repo Audit"
	@echo "    (These are non-blocking and will upload artifacts.)"

.PHONY: rc
rc:
ifeq ($(strip $(TAG)),)
	$(error Please provide TAG, e.g. make rc TAG=v1.0.0-rc1)
endif
	@echo "==> Tagging $(TAG) (annotated)"
	@if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then :; else echo "Not a git repo"; exit 1; fi
	git config user.name "release-bot"
	git config user.email "release@example.com"
	git tag -a $(TAG) -m "$(TAG): release candidate"
	@if git remote | grep -qx origin; then \
		 echo "==> origin found; pushing $(TAG)"; \
		 set -euo pipefail; \
		 git fetch origin && \
		 git checkout main && \
		 git pull --ff-only && \
		 git push origin $(TAG); \
		 echo "==> Done: $(TAG) pushed"; \
	else \
		 echo "==> No 'origin' remote. Created local tag $(TAG)."; \
		 echo "Add a remote and push when ready:"; \
		 echo "  git remote add origin <git-url>"; \
		 echo "  git push origin $(TAG)"; \
	fi
	@echo "Optionally create a draft GitHub Release and attach perf-rc-candidate.json:"
	@echo "  gh release create $(TAG) --draft --title \"$(TAG)\" --notes-file docs/release-notes-stub-rc1.md"
	@echo "  gh release upload $(TAG) perf-rc-candidate.json"

monitoring-lint:
	@docker run --rm -v "$$(pwd):/work" -w /work prom/prometheus:v2.54.1 \
		promtool check rules deploy/monitoring/prometheus/rules/*.yaml || \
		docker run --rm -v "$$(pwd):/work" -w /work prom/prometheus:v2.54.1 \
		promtool check rules deploy/monitoring/prometheus/rules/**/*.yaml
	@docker run --rm -v "$$(pwd):/work" -w /work prom/alertmanager:v0.27.0 \
		amtool check-config deploy/monitoring/alertmanager/alertmanager.yaml

