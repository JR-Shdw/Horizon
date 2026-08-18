# slsa.mk, supply-chain lock + audit targets. Vendor alongside slsa-lock.sh,
# then add to the project Makefile:   include slsa.mk
#
# Convention: each `*requirements*.in` -> hash-locked `*.txt` (--require-hashes).
# Bump a version in a *.in, run `make slsa-update`, review the *.txt diff, commit.

SLSA_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

.PHONY: slsa-lock slsa-audit slsa-update

slsa-lock: ## SLSA rehash : compile chaque *.in -> *.txt hashe
	@sh $(SLSA_DIR)slsa-lock.sh lock

slsa-audit: ## SLSA scan : pip-audit chaque *.txt locke
	@sh $(SLSA_DIR)slsa-lock.sh audit

slsa-update: ## SLSA bump : rehash + scan (apres edition d'un *.in)
	@sh $(SLSA_DIR)slsa-lock.sh update
