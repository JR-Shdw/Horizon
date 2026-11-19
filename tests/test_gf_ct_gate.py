"""Exercise assembly discovery and fail-closed checks without a Rust build."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SYMBOLS = (
    "rhorizon_gf256_ct_clmul",
    "rhorizon_gf256_ct_reduce",
    "rhorizon_gf256_ct_mul",
)


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("valid", "GF(256) constant-time asm gate : PASS"),
        ("branch", "conditional branch(es) detected"),
        ("missing-symbol", "symbol not found"),
        ("missing-file", "asm file not produced"),
        ("build-failure", "fixture compiler failed"),
    ],
)
def test_assembly_gate(tmp_path: Path, arch: str, mode: str, expected: str) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uname = bin_dir / "uname"
    uname.write_text(f"#!/bin/sh\nprintf '%s\\n' '{arch}'\n")
    uname.chmod(0o755)

    instruction = "cmove %eax, %ebx" if arch == "x86_64" else "csel w0, w1, w2, eq"
    if mode == "branch":
        instruction = "jne .Lbad" if arch == "x86_64" else "cbnz w0, .Lbad"
    symbols = SYMBOLS[:-1] if mode == "missing-symbol" else SYMBOLS
    assembly = "\n".join(
        f"{symbol}:\n\t{instruction}\n\tret\n.Lfunc_end{i}:"
        for i, symbol in enumerate(symbols)
    )
    fixture = tmp_path / "fixture.s"
    fixture.write_text(assembly)
    emitted_path = tmp_path / "emitted-path"
    cargo = bin_dir / "cargo"
    cargo.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "output = pathlib.Path(next(a.removeprefix('--emit=asm=') "
        "for a in sys.argv if a.startswith('--emit=asm=')))\n"
        "pathlib.Path(os.environ['EMITTED_PATH']).write_text(str(output))\n"
        "if os.environ['GATE_MODE'] == 'build-failure':\n"
        "    sys.exit('fixture compiler failed')\n"
        "if os.environ['GATE_MODE'] != 'missing-file':\n"
        "    output.write_text(pathlib.Path(os.environ['ASM_FIXTURE']).read_text())\n"
    )
    cargo.chmod(0o755)

    # A previous successful build must never mask missing output in this run.
    target = tmp_path / "target" / "release" / "deps"
    target.mkdir(parents=True)
    (target / "rhorizon_crypto.s").write_text(
        "\n".join(
            f"{symbol}:\n\tret\n.Lfunc_end{i}:" for i, symbol in enumerate(SYMBOLS)
        )
    )
    result = subprocess.run(
        ["bash", str(ROOT / "tools" / "check-gf-ct.sh")],
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "TMPDIR": str(tmp_path),
            "CARGO_TARGET_DIR": str(target.parents[1]),
            "GATE_MODE": mode,
            "ASM_FIXTURE": str(fixture),
            "EMITTED_PATH": str(emitted_path),
        },
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert (result.returncode == 0) == (mode == "valid"), result.stdout + result.stderr
    assert expected in result.stdout + result.stderr
    assert not Path(emitted_path.read_text()).parent.exists()
