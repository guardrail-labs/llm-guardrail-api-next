.PHONY: help up down logs k8s-apply k8s-delete

help:
	@echo "Targets:"
	@echo "  up           - docker compose up (deploy/compose)"
	@echo "  down         - docker compose down"
	@echo "  logs         - docker compose logs -f"
	@echo "  k8s-apply    - kubectl apply -k deploy/k8s"
	@echo "  k8s-delete   - kubectl delete -k deploy/k8s"

up:
	cd deploy/compose && docker compose --env-file .env up -d

down:
	cd deploy/compose && docker compose down

logs:
	cd deploy/compose && docker compose logs -f

k8s-apply:
	kubectl apply -k deploy/k8s

k8s-delete:
	kubectl delete -k deploy/k8s
