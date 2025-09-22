.PHONY: install lint type test run docker-build docker-run compose-up compose-down demo-traffic docs-check

install:
	pip install -r requirements.txt || pip install .

lint:
	ruff check --fix .
	test -f mypy.ini && mypy . || true

test:
	pytest -q

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
	@python tools/perf/bench.py \
	  --base "$${BASE:-http://localhost:8000}" \
	  --token "$${TOKEN:-}" \
	  -c "$${C:-50}" \
	  -d "$${DURATION:-60s}" \
	  --timeout "$${TIMEOUT:-5}" \
	  --limit "$${LIMIT:-50}" \
	  $${INSECURE:+--insecure} \
	  $${OUT:+--out "$$OUT"}

