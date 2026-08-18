"""Static safety contracts for the two-pool container launcher."""

from pathlib import Path

ROOT = Path(__file__).parent.parent
LAUNCHER = ROOT / "api/run-api.sh"


def test_embedded_mode_keeps_single_pool_compatibility():
    source = LAUNCHER.read_text()
    embedded = source.split('if [ "$custody_mode" = embedded ]; then', 1)[1].split(
        "\nfi", 1
    )[0]
    assert "exec python -m uvicorn app.main:app" in embedded
    assert "RH_PROCESS_ROLE=api" in embedded


def test_uvicorn_preserves_kernel_peer_for_proxy_trust_checks():
    source = LAUNCHER.read_text()
    assert "--no-proxy-headers" in source


def test_separated_mode_starts_custodian_before_disposable_api():
    """The pool comes up, is proven ready, and only then serves the public.

    The custodians now live behind run-python-custodians.sh, one uvicorn per
    slot on its own socket, so the readiness gate counts sockets the way the
    rust branch does instead of waiting on a single shared listener. A shared
    listener cannot name a process, which is what forced the control plane to
    re-dial until the kernel handed over the master.
    """
    source = LAUNCHER.read_text()
    custody_start = source.index("run-python-custodians.sh")
    socket_gate = source.index("custodian-${HOSTNAME:-$(hostname")
    api_start = source.index("RH_PROCESS_ROLE=api", custody_start)
    assert custody_start < socket_gate < api_start
    assert '--workers "$api_workers"' in source


def test_python_custodians_are_individually_addressable():
    pool = ROOT / "api/run-python-custodians.sh"
    source = pool.read_text()
    # One process per slot, each on its own socket, each told which slot it is
    # so it can publish that socket for the control plane to address.
    assert "RH_CUSTODIAN_SLOT=" in source
    assert "--workers 1" in source
    assert 'socket_for() { echo "$runtime_dir/custodian-$host-$1.sock"; }' in source
    # Same stale-socket lesson as the rust launcher: liveness is decided by a
    # connect probe before any process starts, never by blind unlink.
    assert "refusing symlinked custodian socket" in source
    assert "python -m app.socket_paths" in source
    first_start = source.index('start_slot "$slot"')
    probe = source.rindex("python -m app.socket_paths", 0, first_start)
    assert probe < source.index('start_slot "$slot"')
    assert '[ ! -e "$socket" ] || rm -f "$socket"' not in source


def test_python_launcher_unlinks_sockets_before_reaping_children():
    source = (ROOT / "api/run-python-custodians.sh").read_text()
    cleanup = source.split("cleanup() {", 1)[1].split("\n}", 1)[0]
    assert cleanup.index('rm -f "$socket"') < cleanup.index('wait "$slot_pid"')


def test_core_dump_policy_is_inherited_by_every_custody_backend():
    for launcher in (
        ROOT / "api/run-api.sh",
        ROOT / "api/run-python-custodians.sh",
        ROOT / "api/run-rust-custodians.sh",
    ):
        source = launcher.read_text()
        hardening = source.index("ulimit -S -c 0")
        assert hardening < source.index("python", hardening)
        assert "ulimit -H -c 0" in source


def test_launcher_generates_private_capability_and_couples_supervisors():
    source = LAUNCHER.read_text()
    assert "secrets.token_hex(32)" in source
    assert 'chmod 600 "$custodian_token"' in source
    assert 'while kill -0 "$custodian_pid"' in source
    assert 'kill -TERM "$api_pid"' in source


def test_rust_backend_is_explicit_and_starts_standalone_fixed_slots():
    source = LAUNCHER.read_text()
    assert "RH_CUSTODY_BACKEND must be python or rust" in source
    assert "RH_CUSTODY_BACKEND=rust requires RH_CUSTODY_MODE=separated" in source
    rust_start = source.index('"$script_dir/run-rust-custodians.sh" &')
    rust_socket_gate = source.index('[ -S "$runtime_dir/rust-custodian-$slot.sock" ]')
    api_start = source.index("RH_PROCESS_ROLE=api", rust_start)
    assert rust_start < rust_socket_gate < api_start
    # The pool is launched with the RESOLVED shape, not the configured one: a
    # configuration that has moved ahead of the durable state names a shape
    # that holds no shares, and launching it stops the API from starting at
    # all. Resolution must therefore happen before the pool does.
    assert 'RH_RUST_CUSTODIAN_SLOTS="$launch_slots"' in source
    assert 'RH_RUST_CUSTODIAN_THRESHOLD="$launch_threshold"' in source
    resolve = source.index("python -m app.custody_launch")
    assert resolve < rust_start
    # And an unresolvable topology refuses to start rather than guessing.
    assert (
        "refusing to start: could not resolve the custodian launch topology" in source
    )


def test_rust_launcher_is_resolved_beside_this_script_not_hardcoded():
    """The image keeps both scripts in /app, so $0-relative resolution is
    identical there, but a source tree can drive the same production launcher
    natively. A hardcoded /app path silently breaks every non-container run."""
    source = LAUNCHER.read_text()
    assert 'script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)' in source
    assert "/app/run-rust-custodians.sh" not in source


def test_rust_launcher_reclaims_an_orphaned_socket_instead_of_wedging():
    """A leftover socket must not be able to seal a node permanently.

    The launcher used to abort on `[ -e "$socket" ]`, which is a test of the
    INODE, not of ownership. The EXIT trap unlinks sockets only after waiting
    on every child, so a stop-timeout SIGKILL strands them; the next start
    then refused the first leftover and `exit 1`-ed the whole loop. Observed
    on the HA lab: slot 1 up, slot 2 refused, slot 3 never reached, pool stuck
    below `--threshold 2`, and /unseal 503-ing forever with no way back.

    Liveness is therefore decided by the same fail-closed connect-probe the
    share sweep uses, via app.socket_paths, rather than by a second and cruder
    rule written in shell.
    """
    source = (ROOT / "api/run-rust-custodians.sh").read_text()
    # The inode-existence abort is gone.
    assert "refusing existing custodian socket" not in source
    # Liveness is delegated, and delegated BEFORE any slot is started, so one
    # leftover cannot decide the fate of the slots after it.
    probe = source.index("python -m app.socket_paths")
    first_start = source.index('start_slot "$slot"')
    assert probe < first_start
    # A probe that cannot answer -- including a missing interpreter -- refuses
    # rather than unlinking on a guess.
    assert "refusing to start the custodian pool" in source
    # A symlink is still refused outright, as in the python launcher.
    assert "refusing symlinked custodian socket" in source


def test_rust_launcher_unlinks_sockets_before_reaping_children():
    """Ordering is the whole fix: systemd SIGKILLs the cgroup at TimeoutStopSec.

    With the unlink after the `wait`, a shutdown that outlived the stop timeout
    never reached it and leaked every socket -- which is how a CLEAN stop still
    stranded rust-custodian-2/3.sock on the lab. The pool is going down once
    TERM is sent, so the inode can go first.
    """
    source = (ROOT / "api/run-rust-custodians.sh").read_text()
    cleanup = source.split("cleanup() {", 1)[1].split("\n}", 1)[0]
    unlink = cleanup.index('rm -f "$socket"')
    reap = cleanup.index('wait "$slot_pid"')
    assert unlink < reap, "sockets must be unlinked before waiting on children"
