#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# k8s smoke test: spin an ephemeral k3d cluster, validate rhorizon's k8s
# manifests against a REAL API server (server-side dry-run catches schema /
# RBAC / admission errors that client-side lint misses), apply the base
# namespace + RBAC, assert they land, then tear the cluster down.
#
# Image-free by design: the example workloads reference rhorizon images that
# are not built here, so they are dry-run validated, not scheduled. A full
# image-loaded e2e (deploy vault + assert rh-fetch delivers a secret) is a
# follow-up gated on a local image build.
#
# Prereqs: k3d (run `make k8s-setup` once) + kubectl + docker.
# Run:     make k8s-test   (or  tools/k8s-test.sh)

set -euo pipefail

CLUSTER="${RH_K3D_CLUSTER:-rh-test}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

command -v k3d >/dev/null || { echo "[k8s] k3d not installed -- run: make k8s-setup"; exit 2; }
command -v kubectl >/dev/null || { echo "[k8s] kubectl missing"; exit 2; }

cleanup() { k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[k8s] creating ephemeral k3d cluster: $CLUSTER"
# k3d talks to a Docker API (default /var/run/docker.sock, or $DOCKER_HOST).
# On a rootless-podman host without user-systemd (e.g. node-5) there is no
# reachable Docker socket and k3s cannot run -- fail with guidance, not a
# cryptic dump. Run this tier on a Docker host or via the CI k8s job.
if ! k3d cluster create "$CLUSTER" --wait --timeout 120s; then
  echo "[k8s] k3d could not create a cluster -- no reachable Docker API." >&2
  echo "      Set DOCKER_HOST to a Docker/rootless-podman socket, or run this" >&2
  echo "      tier on a Docker-capable host / in CI (node-5 can't run k3s)." >&2
  exit 2
fi

echo "[k8s] applying base namespace + RBAC + serviceaccount"
kubectl apply -f "$ROOT/k8s/namespace.yml"

echo "[k8s] server-side dry-run of policy + example workloads"
for f in "$ROOT"/k8s/network-policy.yml "$ROOT"/k8s/examples/*.yml; do
  echo "  -- $(basename "$f")"
  kubectl apply --dry-run=server -f "$f"
done

echo "[k8s] asserting the rhorizon namespace + serviceaccount exist"
kubectl get namespace rhorizon >/dev/null
kubectl -n rhorizon get serviceaccount >/dev/null

echo "[k8s] PASS"
