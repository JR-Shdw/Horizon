.PHONY: help up down build restart logs ps lint lint-fix test test-cov db-shell db-dump db-restore secrets laptop laptop-native rust-check rust-check-fast rust-test rust-wheel-install fuzz-smoke fuzz-list gf-ct-check deps deps-lock deps-audit watch verify-local test-matrix k8s-test native-smoke custody-smoke k8s-e2e retest lab-cleanup chaos-k7-init chaos-k7-check chaos-k7-preflight chaos-k7-24h chaos-k7-24h-detached chaos-k7-24h-high chaos-k7-24h-high-detached chaos-k7-status

# Test-PG host port. 5434 collides with forgejo's PG on some dev hosts, so the
# local test DB defaults to 55434. docker-compose.test.yml reads the same var.
RH_TEST_PG_PORT ?= 55434
export RH_TEST_PG_PORT

# Prefer the repository environment when it exists, while keeping CI and
# distro-package workflows free to provide pytest on PATH or override PYTEST.
PYTEST ?= $(if $(wildcard .venv/bin/pytest),.venv/bin/pytest,pytest)

CHAOS_K7_ENV ?= tools/chaos/k7.env
CHAOS_K7_PROFILE ?= medium

# Aide

help: ## Affiche cette aide
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# Onboarding non-tech (laptop + Claude Desktop / MCP en une commande)

laptop: ## Setup laptop CONTAINER (Docker) : vault + MCP + token Claude (5 min)
	bash tools/quickstart-laptop.sh

laptop-native: ## Setup laptop NATIF (sans Docker, Linux/WSL2) : vault + MCP + token Claude
	bash tools/quickstart-laptop-native.sh

# Stack

up: ## Lance la stack (postgres + api + frontend)
	docker compose up -d

down: ## Arrete la stack
	docker compose down

build: ## Build les images
	docker compose build

restart: ## Restart la stack
	docker compose restart

logs: ## Logs de tous les services
	docker compose logs -f --tail=100

ps: ## Statut des services
	docker compose ps

db-shell: ## Shell psql dans le container postgres
	docker compose exec postgres psql -U rhorizon -d rhorizon

db-dump: ## Dump la BDD chiffree -> backups/rhorizon-<date>.sql.gz
	@mkdir -p backups
	@f="backups/rhorizon-$$(date +%Y%m%d-%H%M%S).sql.gz"; \
	docker compose exec -T postgres pg_dump -U rhorizon -d rhorizon \
		--clean --if-exists --no-owner | gzip > "$$f" \
		&& echo "dumped -> $$f ($$(du -h "$$f" | cut -f1))"

db-restore: ## Restore la BDD depuis FILE=<dump.sql.gz> (DESTRUCTIF -- stop l'API d'abord)
	@test -n "$(FILE)" || { echo "usage: make db-restore FILE=backups/rhorizon-XXXX.sql.gz"; exit 2; }
	@test -f "$(FILE)" || { echo "no such file: $(FILE)"; exit 2; }
	@echo "Restoring $(FILE) into rhorizon -- OVERWRITES current data (Ctrl-C dans 5s)"; sleep 5
	@# Restore-into-empty : drop the schema first so the restore never collides
	@# with objects a fresh-volume initdb pre-seeded from schema.sql (the PG18
	@# major-bump path), and so non --clean dumps restore cleanly too.
	@docker compose exec -T postgres psql -U rhorizon -d rhorizon -q \
		-c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO rhorizon;"
	@gunzip -c "$(FILE)" | docker compose exec -T postgres \
		psql -U rhorizon -d rhorizon -v ON_ERROR_STOP=1 -q \
		&& echo "restored from $(FILE)"

# Dev / CI

lint: ## Lint du code API (ruff)
	ruff check api/
	ruff format --check api/

lint-fix: ## Lint + auto-fix
	ruff check --fix api/
	ruff format api/

# Supply-chain (SLSA) : lockfiles hash-pinnes regeneres dans une image pinnee.
# Pattern vendore dans templates/slsa/ (slsa.mk + slsa-lock.sh) -- auto-decouvre
# tous les *requirements*.in (api/ + tools/ci). Bump -> rehash -> scan : editer
# un *.in puis `make deps`.
export SLSA_PYTHON := 3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a
include templates/slsa/slsa.mk

deps-lock: slsa-lock    ## (alias) rehash les *.txt depuis les *.in
deps-audit: slsa-audit  ## (alias) scan pip-audit des locks
deps: slsa-update       ## (alias) rehash + scan

rust-check: ## Pre-flight Rust local (deny + clippy + test + miri + maturin build)
	bash tools/check-rust.sh

rust-check-fast: ## Idem rust-check sans miri (gain ~5 min)
	bash tools/check-rust.sh --skip-miri

rust-test: ## Tests Rust uniquement (`cargo test` direct marche aussi ; le flag reste par symetrie avec la CI)
	cd api/rust && cargo test --release --locked --no-default-features

rust-test-asan: ## Rust tests sous AddressSanitizer (nightly) -- couvre les paths FFI/socket que miri ne peut PAS atteindre (#[cfg_attr(miri, ignore)])
	cd api/rust && ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 RUSTFLAGS="-Zsanitizer=address" \
		cargo +nightly test --release --no-default-features --target x86_64-unknown-linux-gnu -- --test-threads=1

rust-wheel-install: ## Installe le wheel rhorizon_crypto pre-build dans .venv (skip maturin / rustup)
	bash tools/install-rust-wheel.sh

fuzz-smoke: ## Smoke run des 4 cibles cargo-fuzz (60s chacune, nightly requis)
	bash tools/check-fuzz.sh

fuzz-list: ## Liste les cibles cargo-fuzz definies
	cd api/rust && cargo +nightly fuzz list

gf-ct-check: ## Asm gate constant-time GF(256) (verifie zero conditional jump dans gf256_ct)
	bash tools/check-gf-ct.sh

test: ## Lance les tests pytest (PG de test temporaire)
	@rc=0; \
	docker compose -f docker-compose.test.yml up -d postgres-test && \
	until docker compose -f docker-compose.test.yml exec postgres-test pg_isready -U rhorizon_test -d rhorizon_test 2>/dev/null; do sleep 0.5; done && \
	TEST_DATABASE_URL="postgresql+asyncpg://rhorizon_test:rhorizon_test@localhost:$(RH_TEST_PG_PORT)/rhorizon_test" \
	$(PYTEST) tests/ -v --tb=short --no-cov || rc=$$?; \
	docker compose -f docker-compose.test.yml down || { down_rc=$$?; [ $$rc -ne 0 ] || rc=$$down_rc; }; \
	exit $$rc

test-cov: ## Tests + rapport couverture (HTML dans htmlcov/)
	@rc=0; \
	docker compose -f docker-compose.test.yml up -d postgres-test && \
	until docker compose -f docker-compose.test.yml exec postgres-test pg_isready -U rhorizon_test -d rhorizon_test 2>/dev/null; do sleep 0.5; done && \
	TEST_DATABASE_URL="postgresql+asyncpg://rhorizon_test:rhorizon_test@localhost:$(RH_TEST_PG_PORT)/rhorizon_test" \
	$(PYTEST) tests/ -v --tb=short || rc=$$?; \
	docker compose -f docker-compose.test.yml down || { down_rc=$$?; [ $$rc -ne 0 ] || rc=$$down_rc; }; \
	exit $$rc

# Local test tiers (T0 watch / T1 verify / T2 matrix). See tools/TESTING.md.

watch: ## T0: on every save, lint + run the affected tests (Ctrl-C to stop)
	python tools/watch_tests.py

verify-local: ## T1: full pytest + rust-check (fast) + k8s smoke -- pre-push gate
	$(MAKE) test
	$(MAKE) rust-check-fast
	@$(MAKE) k8s-test || { rc=$$?; if [ $$rc -eq 2 ]; then \
	  echo "[verify] k8s tier skipped (no Docker API on this host)"; \
	  else exit $$rc; fi; }

k8s-test: ## k8s smoke: k3d cluster + validate/apply k8s/ manifests, then teardown
	tools/k8s-test.sh

k8s-setup: ## One-time: install k3d locally (ansible, pinned binary)
	ansible-playbook tools/k3d.yml

native-smoke: ## e2e: native uvicorn N-worker cluster forms (unseal + assert master/followers). Fast, no k8s.
	tools/native-cluster-smoke.sh

custody-smoke: ## e2e: fixed custodian quorum survives disposable API worker replacement.
	tools/custody-smoke.sh

k8s-e2e: ## e2e: build+load images -> helm install -> unseal -> assert cluster on k3d (RH_E2E_DB=inchart|patroni)
	tools/k8s-e2e.sh

retest: ## Post-major-change e2e suite (native smoke + k8s deploy e2e). CI calls this. Exit-2 tiers skip cleanly.
	@$(MAKE) native-smoke || { rc=$$?; [ $$rc -eq 2 ] && echo "[retest] native smoke skipped (no container runtime)" || exit $$rc; }
	@$(MAKE) custody-smoke || { rc=$$?; [ $$rc -eq 2 ] && echo "[retest] custody smoke skipped (no container runtime)" || exit $$rc; }
	@$(MAKE) k8s-e2e      || { rc=$$?; [ $$rc -eq 2 ] && echo "[retest] k8s e2e skipped (no Docker API)"        || exit $$rc; }

lab-cleanup: ## Remove stray LOCAL test artifacts (test PG containers, k3d clusters, smoke/VM work dirs). Run when no test is in flight.
	-docker rm -f rhorizon-test-pg rhorizon-smoke-pg 2>/dev/null
	-docker compose -f docker-compose.test.yml down -v 2>/dev/null
	-if command -v k3d >/dev/null 2>&1; then k3d cluster delete rh-e2e rh-test 2>/dev/null; fi
	-rm -rf /tmp/rh-native-smoke.* /tmp/rh-custody-smoke.* /tmp/rhorizon-vmtest-* 2>/dev/null
	@echo "[lab-cleanup] removed test PG containers, k3d clusters (rh-e2e/rh-test), smoke/VM work dirs"
	@echo "[lab-cleanup] proxmox VMs + the rhorizon_ha lab are managed separately (tofu / rhorizon_ha repo)"

test-matrix: ## T2 (slow): OS VM matrix (8 OSes incl. NetBSD) + native + k8s deploy e2e. Runs all, summarizes.
	@echo "[matrix] OS VMs via qemu (8 OSes, minutes each) + cluster e2e"
	@sshb=$${SSH_PORT:-2222}; pgb=$${PG_PORT:-5433}; i=0; fail=""; \
	for os in arch debian ubuntu freebsd netbsd openbsd rocky opensuse; do \
	  i=$$((i+1)); sp=$$((sshb+i)); pp=$$((pgb+i)); \
	  echo "=== $$os (ssh $$sp / pg $$pp) ==="; \
	  w=0; while ss -ltn 2>/dev/null | grep -qE ":$$sp |:$$pp " && [ $$w -lt 30 ]; do echo "[matrix] waiting for ports $$sp/$$pp to free..."; sleep 2; w=$$((w+2)); done; \
	  if SSH_PORT=$$sp PG_PORT=$$pp tools/test-vm.sh $$os; then echo "[matrix] $$os PASS"; rm -rf /tmp/rhorizon-vmtest-$$os; else echo "[matrix] $$os FAIL (logs: /tmp/rhorizon-vmtest-$$os)"; fail="$$fail $$os"; fi; \
	done; \
	if $(MAKE) retest; then echo "[matrix] cluster-e2e PASS"; else echo "[matrix] cluster-e2e FAIL"; fail="$$fail cluster-e2e"; fi; \
	echo "[matrix] cluster logic also in make test ; full multi-node HA = rhorizon_ha (make reverify)"; \
	if [ -n "$$fail" ]; then echo "[matrix] FAILED:$$fail"; exit 1; fi; \
	echo "[matrix] ALL GREEN (8 OSes + cluster e2e)"

# HA chaos lab. These targets intentionally require an operator-provided env
# file: tokens, node maps, and PVE/docker controls are lab-specific secrets.

chaos-k7-init: ## Create tools/chaos/k7.env from the example template
	@if [ -f "$(CHAOS_K7_ENV)" ]; then \
	  echo "[chaos-k7] $(CHAOS_K7_ENV) already exists"; \
	else \
	  cp tools/chaos/k7.env.example "$(CHAOS_K7_ENV)"; \
	  echo "[chaos-k7] created $(CHAOS_K7_ENV)"; \
	  echo "[chaos-k7] fill token, host map, URL map, and node-control hooks before running"; \
	fi

chaos-k7-check: ## Validate K7 script + required env file before a destructive HA run
	@test -f "$(CHAOS_K7_ENV)" || { echo "[chaos-k7] missing $(CHAOS_K7_ENV); run: make chaos-k7-init"; exit 2; }
	@bash -n tools/chaos/common.sh tools/chaos/k7_random_ha_24h.sh
	@bash -lc 'set -a; source "$(CHAOS_K7_ENV)"; set +a; \
	  export RH_URL="$${RH_URL:-$${RHORIZON_URL:-}}"; \
	  export RH_TOKEN="$${RH_TOKEN:-$${RHORIZON_TOKEN:-}}"; \
	  export RH_TOKEN_FILE="$${RH_TOKEN_FILE:-$${RHORIZON_TOKEN_FILE:-}}"; \
	  export RH_CA_FILE="$${RH_CA_FILE:-$${RHORIZON_CA_FILE:-}}"; \
	  missing=0; \
	  for v in RH_URL CHAOS_HOST_BY_UUID; do \
	    if [[ -z "$${!v:-}" ]]; then echo "[chaos-k7] missing $$v"; missing=1; fi; \
	  done; \
	  if [[ -z "$${RH_TOKEN_FILE:-}" && -z "$${RH_TOKEN:-}" ]]; then \
	    echo "[chaos-k7] missing RH_TOKEN_FILE or RH_TOKEN"; missing=1; \
	  fi; \
	  if [[ -n "$${RH_TOKEN_FILE:-}" && ! -r "$${RH_TOKEN_FILE}" ]]; then echo "[chaos-k7] unreadable RH_TOKEN_FILE=$${RH_TOKEN_FILE}"; missing=1; fi; \
	  if [[ -n "$${RH_CA_FILE:-}" && "$${CHAOS_INSECURE_TLS:-0}" != 1 && ! -r "$${RH_CA_FILE}" ]]; then echo "[chaos-k7] unreadable RH_CA_FILE=$${RH_CA_FILE}"; missing=1; fi; \
	  validate_map() { local name="$$1" value="$$2" json; [[ -f "$$value" ]] && json="$$(< "$$value")" || json="$$value"; jq -e '\''type == "object"'\'' <<< "$$json" >/dev/null || { echo "[chaos-k7] $$name must be a JSON object or path"; missing=1; }; }; \
	  [[ -z "$${CHAOS_HOST_BY_UUID:-}" ]] || validate_map CHAOS_HOST_BY_UUID "$${CHAOS_HOST_BY_UUID}"; \
	  [[ -z "$${CHAOS_URL_BY_UUID:-}" ]] || validate_map CHAOS_URL_BY_UUID "$${CHAOS_URL_BY_UUID}"; \
	  exit $$missing'
	@echo "[chaos-k7] check passed"

chaos-k7-preflight: chaos-k7-check ## Probe K7 topology, TLS, readiness, audit and node-control access without injecting a fault
	@bash -lc 'set -a; source "$(CHAOS_K7_ENV)"; set +a; \
	  export CHAOS_PREFLIGHT_ONLY=1; \
	  exec tools/chaos/k7_random_ha_24h.sh'

chaos-k7-24h: chaos-k7-check ## Run K7 foreground for 24h load/fault injection + final evidence
	@bash -lc 'set -a; source "$(CHAOS_K7_ENV)"; set +a; \
	  export CHAOS_LOAD_PROFILE="$${CHAOS_LOAD_PROFILE:-$(CHAOS_K7_PROFILE)}"; \
	  export CHAOS_DURATION_SECS="$${CHAOS_DURATION_SECS:-86400}"; \
	  exec tools/chaos/k7_random_ha_24h.sh'

chaos-k7-24h-detached: chaos-k7-check ## Run K7 detached with nohup; evidence lands under tools/chaos/results/
	@mkdir -p tools/chaos/results
	@bash -lc 'set -a; source "$(CHAOS_K7_ENV)"; set +a; \
	  export CHAOS_LOAD_PROFILE="$${CHAOS_LOAD_PROFILE:-$(CHAOS_K7_PROFILE)}"; \
	  export CHAOS_DURATION_SECS="$${CHAOS_DURATION_SECS:-86400}"; \
	  log="tools/chaos/results/k7-nohup-$$(date -u +%Y%m%dT%H%M%SZ).log"; \
	  nohup tools/chaos/k7_random_ha_24h.sh > "$$log" 2>&1 & \
	  echo $$! > tools/chaos/results/k7-launch.pid; \
	  echo "[chaos-k7] pid=$$!"; \
	  echo "[chaos-k7] launcher log=$$log"; \
	  echo "[chaos-k7] evidence=tools/chaos/results/k7-<start_ts>-<run_id>/"'

chaos-k7-24h-high: ## Run K7 foreground with the high load profile
	@$(MAKE) chaos-k7-24h CHAOS_K7_PROFILE=high

chaos-k7-24h-high-detached: ## Run K7 detached with the high load profile
	@$(MAKE) chaos-k7-24h-detached CHAOS_K7_PROFILE=high

chaos-k7-status: ## Show current K7 pid and newest evidence directory
	@if [ -f tools/chaos/results/k7.pid ] && kill -0 "$$(cat tools/chaos/results/k7.pid)" 2>/dev/null; then \
	  echo "[chaos-k7] active pid=$$(cat tools/chaos/results/k7.pid)"; \
	else \
	  echo "[chaos-k7] no active k7.pid"; \
	fi
	@latest=$$(find tools/chaos/results -mindepth 1 -maxdepth 1 -type d -name 'k7-*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | cut -d' ' -f2-); \
	if [ -n "$$latest" ]; then \
	  echo "[chaos-k7] latest evidence=$$latest"; \
	  test -f "$$latest/final-summary.json" && jq . "$$latest/final-summary.json" || true; \
	fi

# Secrets

secrets: ## Genere .env avec secrets aleatoires
	@if [ -f .env ]; then echo ".env existe deja, supprimez-le d'abord"; exit 1; fi
	@echo "POSTGRES_DB=rhorizon"           >  .env
	@echo "POSTGRES_USER=rhorizon"         >> .env
	@echo "POSTGRES_PASSWORD=$$(openssl rand -hex 24)" >> .env
	@echo "LISTEN_ADDR=127.0.0.1"        >> .env
	@echo ""
	@echo ".env generated, keep it safe"

# Maintainer-only targets (push / public release) live in Makefile.private,
# which is stripped from the public snapshot. `-include` (leading dash) silently
# no-ops when the file is absent, so the public GitHub Makefile carries none of
# these commands. Kept at the bottom so `help` stays the default goal.
-include Makefile.private
