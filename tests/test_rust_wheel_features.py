"""The two feature spellings that decide whether the wheel links libpython.

`--features pyo3/extension-module` activates the feature on the pyo3 crate and
leaves this crate's CARGO_FEATURE_EXTENSION_MODULE unset, so `build.rs` cannot
see it and adds the libpython link args to the wheel build. That shipped a
wheel linking libpython3.12 once already; the manylinux check rejected it and
the pipeline broke (a644b72).

These are cheap text contracts. The real proof is `maturin build`, which fails
loudly on a non-compliant wheel -- but it runs in CI minutes after a change,
and only there.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CARGO = ROOT / "api/rust/Cargo.toml"
PYPROJECT = ROOT / "api/rust/pyproject.toml"
BUILD_RS = ROOT / "api/rust/build.rs"


def test_maturin_asks_for_the_local_feature_not_the_pyo3_one():
    source = PYPROJECT.read_text()
    assert 'features = ["extension-module"]' in source
    assert 'features = ["pyo3/extension-module"]' not in source


def test_the_local_feature_forwards_to_pyo3():
    """Otherwise the wheel would link libpython for the opposite reason."""
    source = CARGO.read_text()
    assert 'extension-module = ["pyo3/extension-module"]' in source


def test_extension_module_is_not_a_default_feature():
    """A default would put libpython-free linkage on `cargo test` too."""
    source = CARGO.read_text()
    assert "\ndefault = []\n" in source


def test_build_script_honours_both_signals():
    """The env var covers a build driven with the other feature spelling."""
    source = BUILD_RS.read_text()
    assert 'env::var_os("CARGO_FEATURE_EXTENSION_MODULE").is_some()' in source
    assert 'env::var_os("PYO3_BUILD_EXTENSION_MODULE").is_some()' in source
