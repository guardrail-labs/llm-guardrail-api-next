.PHONY: install lint type test run docker-build docker-run compose-up compose-down

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

compose-up:
	docker compose up --build

compose-down:
	docker compose down -v
