"""Contracts for the opt-in standalone Rust custodian pool supervisor."""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "api/run-rust-custodians.sh"


def test_launcher_bootstraps_every_identity_before_starting_daemons():
    source = LAUNCHER.read_text()
    bootstrap = source.index('generate-transport-key --output "$key_file"')
    launch = source.index('"$@" &')
    assert bootstrap < launch
    assert 'generate-control-token --output "$control_token"' in source
    assert '--peer-key "$peer:$peer_public"' in source


def test_launcher_is_opt_in_and_keeps_keys_out_of_runtime_tmpfs():
    source = LAUNCHER.read_text()
    api_launcher = (ROOT / "api/run-api.sh").read_text()
    assert 'if [ "$custody_backend" = rust ]' in api_launcher
    assert "/var/lib/rhorizon/custody" in source
    assert 'key_file="$key_dir/slot-$slot.transport-key"' in source
    assert (
        'share_state="$key_dir/slot-$start_slot_number.$threshold-of-$slots.share-state"'
        in source
    )
    assert '--share-state-file "$share_state"' in source
    assert 'socket="$runtime_dir/rust-custodian-$slot.sock"' in source


def test_launcher_rejects_weak_topologies_and_unknown_socket_replacement():
    source = LAUNCHER.read_text()
    assert "3|5|7|9)" in source
    assert '"$threshold" -lt 2' in source
    # The socket gets the SAME split already applied to the public-key scratch
    # file below: a symlink is refused outright, but our own leftover is
    # cleared rather than wedging the service. Refusing on mere existence
    # aborted the whole start loop at the first stale inode, leaving the pool
    # under threshold and the node sealed with no way back.
    #
    # "Not ours to take over" is still enforced, just decided properly: the
    # fail-closed connect-probe in app.socket_paths refuses a socket with a
    # LIVE listener, and refuses when it cannot tell.
    assert "refusing symlinked custodian socket" in source
    assert "python -m app.socket_paths" in source
    assert "refusing to start the custodian pool" in source
    assert "runtime directory must not be a symlink" in source
    assert "custody key directory must not be a symlink" in source
    # Split into two: a symlink is still refused outright, while our own
    # leftover regular file is cleared instead of wedging the service.
    assert "refusing symlinked public-key scratch file" in source
    assert "refusing non-regular public-key scratch file" in source
    assert "set -C" in source
    assert '[ ! -S "$socket" ] || rm -f "$socket"' in source
    assert '[ "$threshold" = 0 ]' in source


def test_launcher_keeps_the_previous_topology_state_beside_the_target():
    """A reshare relaunch must not write over the shape it may revert to."""
    source = LAUNCHER.read_text()
    assert 'legacy_share_state="$key_dir/slot-$start_slot_number.share-state"' in source
    assert '[ ! -e "$legacy_share_state" ] || \\' in source
    assert '--adopt-share-state-file "$legacy_share_state"' in source
    # The legacy name is only ever passed for adoption, never as the state the
    # daemon writes: that is what keeps two topologies from sharing one file.
    assert '--share-state-file "$legacy_share_state"' not in source


def test_launcher_restarts_only_the_failed_fixed_slot():
    source = LAUNCHER.read_text()
    assert "start_slot()" in source
    assert 'start_slot "$slot"' in source
    assert "Rust custodian slot $slot exited ($status); restarting" in source
    assert "Rust custodian slot $slot restarted sealed" in source
    assert "Rust custodian exited; stopping pool" not in source


def test_launcher_fails_before_bootstrap_for_weak_topology(tmp_path):
    result = subprocess.run(
        [str(LAUNCHER)],
        env={**os.environ, "RH_RUST_CUSTODIAN_SLOTS": "1"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "must be 3, 5, 7, or 9" in result.stderr


def test_launcher_refuses_symlink_directory_and_scratch_replacement(tmp_path):
    real_runtime = tmp_path / "real-run"
    real_runtime.mkdir()
    runtime_link = tmp_path / "run"
    runtime_link.symlink_to(real_runtime, target_is_directory=True)
    common = {
        **os.environ,
        "RH_RUNTIME_DIR": str(runtime_link),
        "RH_RUST_CUSTODIAN_KEY_DIR": str(tmp_path / "keys"),
    }
    symlink_result = subprocess.run(
        [str(LAUNCHER)],
        env=common,
        text=True,
        capture_output=True,
        check=False,
    )
    assert symlink_result.returncode == 2
    assert "runtime directory must not be a symlink" in symlink_result.stderr

    runtime = tmp_path / "clean-run"
    runtime.mkdir(mode=0o700)
    token = runtime / "custodian-control.token"
    token.write_text("00" * 32 + "\n")
    token.chmod(0o600)
    # A SYMLINK is still refused: the redirect that fills this file would
    # write through it, to wherever it points.
    planted = runtime / "rust-custodian-1.public"
    planted.symlink_to(tmp_path / "elsewhere")
    symlinked_scratch = subprocess.run(
        [str(LAUNCHER)],
        env={
            **os.environ,
            "RH_RUNTIME_DIR": str(runtime),
            "RH_RUST_CUSTODIAN_KEY_DIR": str(tmp_path / "clean-keys"),
            "RH_RUST_CUSTODIAN_BINARY": "/does/not/exist",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert symlinked_scratch.returncode == 1
    assert "refusing symlinked public-key scratch file" in symlinked_scratch.stderr
    assert not (tmp_path / "elsewhere").exists()
    planted.unlink()

    # A leftover REGULAR file is this service's own litter and is cleared. It
    # cannot be a plant that survives: the launcher rewrites the file from the
    # slot's real transport key, so whatever was there is destroyed either
    # way. Refusing it instead wedged a real node into a permanent crash loop,
    # because systemd preserves the runtime directory across restarts.
    (runtime / "rust-custodian-1.public").write_text("stale-from-a-dead-run\n")
    stale_scratch = subprocess.run(
        [str(LAUNCHER)],
        env={
            **os.environ,
            "RH_RUNTIME_DIR": str(runtime),
            "RH_RUST_CUSTODIAN_KEY_DIR": str(tmp_path / "clean-keys"),
            "RH_RUST_CUSTODIAN_BINARY": "/does/not/exist",
        },
        text=True,
        capture_output=True,
        check=False,
    )
    # It gets past the scratch guard and fails on the missing binary instead.
    assert "public-key scratch file" not in stale_scratch.stderr


def test_a_stale_scratch_file_does_not_wedge_every_future_start():
    """One unclean exit must not crash-loop the service forever.

    The redirect that captures a slot's public key CREATES the scratch file
    before the custodian binary runs, so even a failed exec leaves one behind.
    Under systemd with RuntimeDirectoryPreserve the runtime directory survives
    restarts, so refusing outright meant the service could never start again
    without a human deleting the file -- invisible in a container, where /run
    is a fresh tmpfs per start.

    A symlink is still refused: the removal is only ever of a regular file, in
    a directory this service owns at 0700.
    """
    source = LAUNCHER.read_text()
    assert "refusing symlinked public-key scratch file" in source
    assert "refusing non-regular public-key scratch file" in source
    symlink_gate = source.index('if [ -L "$public_file" ]; then')
    regular_gate = source.index('if [ ! -f "$public_file" ]; then')
    removal = source.index('rm -f "$public_file"')
    # The symlink refusal comes first, and nothing is removed before the
    # regular-file check has passed.
    assert symlink_gate < regular_gate < removal


def test_share_state_is_not_persisted_without_an_off_disk_key_provider(tmp_path):
    """THE at-rest contract. Persisting must never be the default again.

    The sealed state file is opened with a key derived from the transport key
    stored beside it, so a copy of the key directory yields shares -- and with
    threshold-many slots co-located, the whole sub-key bundle, no password.
    What it buys is narrow: a surviving quorum already refills an empty slot,
    so the file only matters below threshold (simultaneous multi-daemon loss,
    or a reboot). Off until a provider can wrap the transport key off-disk.
    """
    source = LAUNCHER.read_text()
    assert "state_provider=${RH_RUST_CUSTODIAN_STATE_PROVIDER:-" in source
    # The flag is passed only inside the provider branch, never unconditionally.
    assert 'if [ "$state_provider" != none ]; then' in source
    assert '--share-state-file "$share_state"' in source
    persist_flag = source.index('--share-state-file "$share_state"')
    branch = source.index('if [ "$state_provider" != none ]; then')
    assert branch < persist_flag, "persistence must sit inside the provider branch"

    # A provider that is not built yet must REFUSE, not quietly fall back to
    # writing an unprotected file -- that is the failure that would hand an
    # operator the opposite of what they asked for.
    for provider in ("tpm2", "yubikey"):
        result = subprocess.run(
            ["sh", str(LAUNCHER)],
            env={
                **os.environ,
                "RH_RUST_CUSTODIAN_STATE_PROVIDER": provider,
                "RH_RUNTIME_DIR": str(tmp_path / "run"),
                "RH_RUST_CUSTODIAN_KEY_DIR": str(tmp_path / "keys"),
                "RH_RUST_CUSTODIAN_BINARY": "/does/not/exist",
            },
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 2, result.stderr
        assert "not implemented yet" in result.stderr


def test_a_leftover_state_file_is_removed_when_persistence_is_off(tmp_path):
    """Upgrading must not leave the material behind that the change removes."""
    key_dir = tmp_path / "keys"
    key_dir.mkdir(parents=True)
    stale = key_dir / "slot-1.2-of-3.share-state"
    stale.write_bytes(b"RHSS" + b"\x00" * 64)

    subprocess.run(
        ["sh", str(LAUNCHER)],
        env={
            **os.environ,
            "RH_RUNTIME_DIR": str(tmp_path / "run"),
            "RH_RUST_CUSTODIAN_KEY_DIR": str(key_dir),
            "RH_RUST_CUSTODIAN_BINARY": "/does/not/exist",
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert not stale.exists(), "a persisted share survived an unpersisted start"
