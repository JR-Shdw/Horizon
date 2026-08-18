"""The API image carries the opt-in Rust custodian without launching it."""

from pathlib import Path


def test_api_image_packages_but_does_not_start_rust_custodian():
    repository = Path(__file__).resolve().parents[1]
    dockerfile = (repository / "api" / "Dockerfile").read_text()

    assert "cargo build --release --locked -p rhorizon-custodian" in dockerfile
    assert (
        "COPY --from=rust-builder /build/target/release/rhorizon-custodian "
        "/usr/local/bin/rhorizon-custodian"
    ) in dockerfile
    assert 'CMD ["/app/run-api.sh"]' in dockerfile
    assert "COPY api/run-rust-custodians.sh ./run-rust-custodians.sh" in dockerfile
    assert "chmod 755 /app/run-api.sh /app/run-rust-custodians.sh" in dockerfile
    assert "run-rust-custodians.sh" not in dockerfile.split("CMD", maxsplit=1)[1]
