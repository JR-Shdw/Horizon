# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deployment-level safety checks for the default Helm probes."""

from pathlib import Path

import yaml
from api.app.dynamic_engines.loader import BUILTIN_MODULES


def test_api_readiness_uses_the_full_readiness_endpoint():
    values_path = Path(__file__).parents[1] / "helm" / "rhorizon" / "values.yaml"
    values = yaml.safe_load(values_path.read_text())

    assert values["api"]["livenessProbe"]["httpGet"]["path"] == "/health"
    readiness = values["api"]["readinessProbe"]
    assert readiness["httpGet"]["path"] == "/readiness"
    assert readiness["timeoutSeconds"] > 1
    assert readiness["failureThreshold"] >= 3
    assert values["api"]["custodyMode"] == "embedded"
    assert values["api"]["custodianWorkers"] == 5


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
