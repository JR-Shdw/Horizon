# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deployment-level safety checks for the default Helm probes."""

from pathlib import Path

import yaml
from api.app.dynamic_engines.loader import BUILTIN_MODULES


def test_api_readiness_uses_the_full_readiness_endpoint():
    values_path = Path(__file__).parents[1] / "helm" / "rhorizon" / "values.yaml"
    values = yaml.safe_load(values_path.read_text())

    startup = values["api"]["startupProbe"]
    assert startup["httpGet"]["path"] == "/health"
    assert startup["periodSeconds"] * startup["failureThreshold"] >= 300
    assert values["api"]["livenessProbe"]["httpGet"]["path"] == "/health"
    readiness = values["api"]["readinessProbe"]
    assert readiness["httpGet"]["path"] == "/readiness"
    assert readiness["timeoutSeconds"] > 1
    assert readiness["failureThreshold"] >= 3
    assert values["api"]["custodyMode"] == "embedded"
    assert values["api"]["custodianWorkers"] == 5
    assert values["api"]["maxConcurrentRequests"] == 0

    template = (
        Path(__file__).parents[1]
        / "helm"
        / "rhorizon"
        / "templates"
        / "api-deployment.yaml"
    ).read_text()
    assert "startupProbe:" in template
    assert ".Values.api.startupProbe" in template


def test_separated_custody_values_reach_the_api_container():
    template = (
        Path(__file__).parents[1]
        / "helm"
        / "rhorizon"
        / "templates"
        / "api-deployment.yaml"
    ).read_text()
    assert "name: RH_CUSTODY_MODE" in template
    assert ".Values.api.custodyMode" in template
    assert "name: RH_CUSTODIAN_WORKERS" in template
    assert ".Values.api.custodianWorkers" in template
    assert "name: RH_MAX_CONCURRENT_REQUESTS" in template
    assert ".Values.api.maxConcurrentRequests" in template


def test_ha_uses_persistent_per_pod_identity_and_explicit_mtls_inputs():
    """Structural assertions only: these read the template TEXT.

    Finding a guard's message here does not prove helm refuses to render. A
    typo in the condition, a guard placed after the manifest, or an `{{- if -}}`
    that never evaluates true would all keep the string and lose the guard.
    The .woodpecker/validate.yml `validate-helm` step renders the chart for
    real and asserts each guard actually aborts, with its own message.
    """
    root = Path(__file__).parents[1]
    chart = root / "helm" / "rhorizon"
    values = yaml.safe_load((chart / "values.yaml").read_text())
    api = (chart / "templates" / "api-deployment.yaml").read_text()
    frontend = (chart / "templates" / "frontend-deployment.yaml").read_text()
    headless = (chart / "templates" / "api-headless-service.yaml").read_text()
    network = (chart / "templates" / "networkpolicy.yaml").read_text()

    assert values["api"]["clusterEnabled"] is False
    assert values["api"]["persistence"]["enabled"] is True
    assert "kind: StatefulSet" in api
    assert "volumeClaimTemplates:" in api
    assert "name: RH_CLUSTER_IDENTITY_PERSISTENT" in api
    assert "name: RH_CLUSTER_ADVERTISE_IP" in api
    assert "fieldPath: status.podIP" in api
    assert "api.clusterEnabled=true requires api.proxyTrustedIps" in api
    assert "api.replicas>1 requires api.clusterEnabled=true" in api
    assert "api.haAutoJoin=true requires api.haPasswordSecretName" in api
    assert "name: RH_HA_SERVER_CA_FILE" in api
    assert "name: ha-server-ca" in api
    assert "name: RH_CLUSTER_MTLS" in frontend
    assert "frontend.tls.secretName" in frontend
    assert "clusterIP: None" in headless
    assert ".Values.service.frontend.httpsPort" in network


def test_dynamic_modules_are_explicit_and_mounted_read_only():
    root = Path(__file__).parents[1]
    chart = root / "helm" / "rhorizon"
    values = yaml.safe_load((chart / "values.yaml").read_text())

    assert set(values["api"]["dynamicModules"]) == set(BUILTIN_MODULES)
    assert all(values["api"]["dynamicModules"].values())

    configmap = (chart / "templates" / "dynamic-engines-configmap.yaml").read_text()
    deployment = (chart / "templates" / "api-deployment.yaml").read_text()
    for name in BUILTIN_MODULES:
        assert f".Values.api.dynamicModules.{name}" in configmap
    assert "mountPath: /app/dynamic-engines.ini" in deployment
    assert "readOnly: true" in deployment


def test_the_frontend_is_optional_and_defaults_to_on():
    """The API is the product; the UI is a convenience whose image is not
    published. Leaving it mandatory gives anyone on the public path a
    permanent ImagePullBackOff beside a healthy API."""
    root = Path(__file__).parents[1] / "helm" / "rhorizon"
    values = yaml.safe_load((root / "values.yaml").read_text())
    assert values["frontend"]["enabled"] is True  # unchanged for existing users

    templates = root / "templates"
    for name in ("frontend-deployment.yaml", "frontend-service.yaml"):
        body = (templates / name).read_text()
        assert "if .Values.frontend.enabled" in body, name

    # A PDB or a NetworkPolicy selecting Pods that cannot exist is a dangling
    # selector, not a no-op: the PDB blocks node drains forever.
    assert (
        "and .Values.pdb.frontend.enabled .Values.frontend.enabled"
        in (templates / "pdb.yaml").read_text()
    )
    assert (
        "if .Values.frontend.enabled" in (templates / "networkpolicy.yaml").read_text()
    )


def test_ha_refuses_to_render_without_the_tls_terminator_it_declares():
    """RH_TLS_ENABLED is a declaration api/app/config.py's boot check trusts.
    With no frontend there is no nginx terminating TLS, so claiming it would
    let an HA node boot believing it is reachable over TLS when it is not."""
    api = (
        Path(__file__).parents[1]
        / "helm"
        / "rhorizon"
        / "templates"
        / "api-deployment.yaml"
    ).read_text()
    assert "requires frontend.enabled=true" in api
    assert (
        "or .Values.api.clusterEnabled "
        "(and .Values.frontend.enabled .Values.frontend.tls.enabled)" in api
    )
