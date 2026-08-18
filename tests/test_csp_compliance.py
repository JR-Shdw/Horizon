"""CSP / inline-style regression tests for rhorizon frontend.

Rhorizon ships with a strict CSP:
  - script-src 'self' 'sha256-<hash>'  (no 'unsafe-inline', no 'unsafe-eval')
  - style-src 'self'                   (no 'unsafe-inline')

These tests lock that posture. If someone loosens the CSP or reintroduces
inline styles beyond the current budget, CI fails.
"""

import re
from pathlib import Path

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
NGINX_CONFS = [FRONTEND / "nginx.conf", FRONTEND / "nginx-tls.conf"]
INDEX_HTML = FRONTEND / "index.html"
JS_DIR = FRONTEND / "js"

_STYLE_ATTR_RE = re.compile(r'style="[^"]*"')

# Ratchet: inline style="..." count in JS + index.html.
# Must only decrease. Bump down when you migrate styles to CSS.
_INLINE_STYLE_BUDGET = 0


def _inline_style_sources() -> list[Path]:
    files = []
    if JS_DIR.exists():
        files.extend(sorted(JS_DIR.rglob("*.js")))
    if INDEX_HTML.exists():
        files.append(INDEX_HTML)
    return files


def test_inline_styles_not_regressing():
    """Inline style="..." count stays <= budget."""
    count = 0
    for f in _inline_style_sources():
        count += len(_STYLE_ATTR_RE.findall(f.read_text(encoding="utf-8")))
    assert count <= _INLINE_STYLE_BUDGET, (
        f"Inline styles regressed: {count} > budget {_INLINE_STYLE_BUDGET}. "
        f"Migrate to CSS classes in frontend/css/."
    )


def test_nginx_csp_style_src_locked():
    """All nginx confs must keep style-src 'self' with no unsafe-* tokens."""
    for conf in NGINX_CONFS:
        if not conf.exists():
            continue
        text = conf.read_text(encoding="utf-8")
        m = re.search(r"style-src[^;]*", text)
        assert m, f"{conf.name} has no style-src directive"
        directive = m.group(0)
        assert "'self'" in directive, (
            f"{conf.name} style-src missing 'self': {directive}"
        )
        assert "'unsafe-inline'" not in directive, (
            f"{conf.name} style-src must never include 'unsafe-inline': {directive}"
        )
        assert "'unsafe-eval'" not in directive, (
            f"{conf.name} style-src must never include 'unsafe-eval': {directive}"
        )


def test_nginx_csp_script_src_locked():
    """All nginx confs must keep script-src strict (self + hash only)."""
    for conf in NGINX_CONFS:
        if not conf.exists():
            continue
        text = conf.read_text(encoding="utf-8")
        m = re.search(r"script-src[^;]*", text)
        assert m, f"{conf.name} has no script-src directive"
        directive = m.group(0)
        assert "'self'" in directive, (
            f"{conf.name} script-src missing 'self': {directive}"
        )
        assert "'unsafe-inline'" not in directive, (
            f"{conf.name} script-src must never include 'unsafe-inline': {directive}"
        )
        assert "'unsafe-eval'" not in directive, (
            f"{conf.name} script-src must never include 'unsafe-eval': {directive}"
        )


def test_nginx_csp_default_src_self():
    """CSP default-src must be 'self' (no wildcards, no unsafe-*)."""
    for conf in NGINX_CONFS:
        if not conf.exists():
            continue
        text = conf.read_text(encoding="utf-8")
        m = re.search(r"default-src[^;]*", text)
        assert m, f"{conf.name} has no default-src directive"
        directive = m.group(0)
        assert "'self'" in directive or "'none'" in directive, (
            f"{conf.name} default-src must be 'self' or 'none': {directive}"
        )
        assert "'unsafe-inline'" not in directive, (
            f"{conf.name} default-src must never include 'unsafe-inline': {directive}"
        )
        assert "'unsafe-eval'" not in directive, (
            f"{conf.name} default-src must never include 'unsafe-eval': {directive}"
        )
        assert "*" not in directive.replace("'", ""), (
            f"{conf.name} default-src must not use wildcards: {directive}"
        )


def test_no_inline_event_handlers():
    """No onclick/onchange/... attributes in frontend (CSP script-src compliance)."""
    pattern = re.compile(
        r"\bon(click|change|input|submit|keydown|keyup|mousedown|"
        r"mouseup|focus|blur|load)\s*=\s*[\"']",
        re.IGNORECASE,
    )
    violations = []
    for f in _inline_style_sources():
        text = f.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                violations.append(f"{f.name}:{i} - {line.strip()[:100]}")
    assert not violations, (
        f"{len(violations)} inline event handlers found (CSP violation):\n"
        + "\n".join(violations[:20])
    )
