"""Unit tests for VaultState - no database needed."""

import os
import time

import pytest
from api.app.vault_state import VaultSealedError, VaultState

# VaultState


class TestVaultState:
    def test_initial_state(self):
        # Review #6: hmac_key/dek_key/audit_key properties were removed -
        # we test functional state instead (operations raise VaultSealedError).
        v = VaultState()
        assert v.sealed is True
        assert v.aesgcm is None
        assert v.uptime is None
        assert v.shamir_progress == 0
        assert v.pending_shares == []
        assert v.has_prev_hmac is False

    @pytest.mark.parametrize("epoch", [True, -1, 1.5, "1"])
    def test_set_key_epoch_rejects_invalid_values(self, epoch):
        v = VaultState()
        with pytest.raises(ValueError):
            v.set_key_epoch(epoch)

    @pytest.mark.asyncio
    async def test_unseal_sets_keys(self):
        v = VaultState()
        keys = {
            "hmac_key": os.urandom(32),
            "dek_key": os.urandom(32),
            "audit_key": os.urandom(32),
            "ha_wrap_key": os.urandom(32),
            "pki_wrap_key": os.urandom(32),
        }
        v.unseal(keys)
        assert v.sealed is False
        # Operation methods work after unseal, keys are reachable via Rust.
        assert len(await v.hmac_sha512_hex("probe")) == 128  # SHA-512 hex
        assert await v.audit_sign("payload") != ""
        ct, nonce = await v.aesgcm_encrypt(b"x", b"aad")
        assert await v.aesgcm_decrypt(ct, nonce, b"aad") == b"x"
        assert v.aesgcm is not None

    @pytest.mark.asyncio
    async def test_seal_zeros_keys(self):
        v = VaultState()
        keys = {
            "hmac_key": os.urandom(32),
            "dek_key": os.urandom(32),
            "audit_key": os.urandom(32),
            "ha_wrap_key": os.urandom(32),
            "pki_wrap_key": os.urandom(32),
        }
        v.unseal(keys)
        v.seal()
        assert v.sealed is True
        assert v.aesgcm is None
        # Operations raise VaultSealedError after seal (no plaintext leak)
        with pytest.raises(VaultSealedError):
            await v.hmac_sha512_hex("probe")
        with pytest.raises(VaultSealedError):
            await v.aesgcm_encrypt(b"x", b"aad")
        with pytest.raises(VaultSealedError):
            await v.audit_sign("payload")

    def test_uptime_when_unsealed(self):
        v = VaultState()
        keys = {
            "hmac_key": os.urandom(32),
            "dek_key": os.urandom(32),
            "audit_key": os.urandom(32),
            "ha_wrap_key": os.urandom(32),
            "pki_wrap_key": os.urandom(32),
        }
        v.unseal(keys)
        uptime = v.uptime
        assert uptime is not None
        assert "h" in uptime and "m" in uptime  # e.g. "0h00m"

    def test_uptime_none_when_sealed(self):
        v = VaultState()
        assert v.uptime is None

    def test_require_unsealed_raises_when_sealed(self):
        v = VaultState()
        with pytest.raises(VaultSealedError):
            v.require_unsealed()

    def test_require_unsealed_passes_when_unsealed(self):
        v = VaultState()
        v.unseal(
            {
                "hmac_key": os.urandom(32),
                "dek_key": os.urandom(32),
                "audit_key": os.urandom(32),
                "ha_wrap_key": os.urandom(32),
                "pki_wrap_key": os.urandom(32),
            }
        )
        v.require_unsealed()  # should not raise

    # -- Shamir share accumulation --

    def test_add_share(self):
        v = VaultState()
        share1 = b"\x01" + os.urandom(160)
        share2 = b"\x02" + os.urandom(160)
        assert v.add_share(share1) == 1
        assert v.add_share(share2) == 2
        assert v.shamir_progress == 2

    def test_add_share_rejects_duplicate_index(self):
        v = VaultState()
        share1 = b"\x01" + os.urandom(160)
        v.add_share(share1)
        assert v.add_share(share1) == 1

    def test_add_share_conflicting_index_clears_pending_set(self):
        v = VaultState()
        v.add_share(b"\x01" + os.urandom(160))
        with pytest.raises(ValueError, match="Conflicting"):
            v.add_share(b"\x01" + os.urandom(160))
        assert v.shamir_progress == 0

    @pytest.mark.parametrize(
        "share",
        [
            b"\x01" + os.urandom(159),
            b"\x01" + os.urandom(161),
            b"\x00" + os.urandom(160),
        ],
    )
    def test_add_share_rejects_invalid_size_or_index(self, share):
        v = VaultState()
        with pytest.raises(ValueError):
            v.add_share(share)

    def test_add_share_accepts_maximum_coordinate(self):
        v = VaultState()
        assert v.add_share(b"\xff" + os.urandom(160)) == 1

    @pytest.mark.parametrize("key_size", [0, 31, 33, 64])
    def test_unseal_rejects_invalid_runtime_key_length(self, key_size):
        v = VaultState()
        keys = {
            "hmac_key": os.urandom(32),
            "dek_key": os.urandom(32),
            "audit_key": os.urandom(32),
            "ha_wrap_key": os.urandom(32),
            "pki_wrap_key": os.urandom(key_size),
        }
        with pytest.raises(ValueError, match="pki_wrap_key must be exactly 32 bytes"):
            v.unseal(keys)
        assert v.sealed is True

    def test_unseal_rejects_missing_runtime_key(self):
        v = VaultState()
        keys = {
            "hmac_key": os.urandom(32),
            "dek_key": os.urandom(32),
            "audit_key": os.urandom(32),
            "ha_wrap_key": os.urandom(32),
        }
        with pytest.raises(ValueError, match="missing runtime keys: pki_wrap_key"):
            v.unseal(keys)
        assert v.sealed is True

    def test_set_prev_hmac_rejects_invalid_length(self):
        v = VaultState()
        with pytest.raises(
            ValueError, match="previous HMAC key must be exactly 32 bytes"
        ):
            v.set_prev_hmac(os.urandom(64))

    def test_pending_shares_is_copy(self):
        v = VaultState()
        share = b"\x01" + os.urandom(160)
        v.add_share(share)
        copies = v.pending_shares
        copies.clear()
        assert v.shamir_progress == 1  # original unaffected

    def test_clear_shares(self):
        v = VaultState()
        v.add_share(b"\x01" + os.urandom(160))
        v.add_share(b"\x02" + os.urandom(160))
        retained = v.pending_shares
        v.clear_shares()
        assert v.shamir_progress == 0
        assert all(not any(share) for share in retained)

    def test_pending_shares_expire_and_zeroize(self, monkeypatch):
        import api.app.vault_state as state_mod

        now = 1000.0
        monkeypatch.setattr(state_mod.time, "monotonic", lambda: now)
        v = VaultState()
        v.add_share(b"\x01" + os.urandom(160))
        retained = v.pending_shares
        now += state_mod._SHAMIR_PENDING_TTL_SECS
        assert v.shamir_progress == 0
        assert all(not any(share) for share in retained)

    def test_seal_clears_shares(self):
        v = VaultState()
        v.unseal(
            {
                "hmac_key": os.urandom(32),
                "dek_key": os.urandom(32),
                "audit_key": os.urandom(32),
                "ha_wrap_key": os.urandom(32),
                "pki_wrap_key": os.urandom(32),
            }
        )
        v.add_share(b"\x01" + os.urandom(160))
        retained = v.pending_shares
        v.seal()
        assert v.shamir_progress == 0
        assert all(not any(share) for share in retained)

    # -- 2FA cache --

    def test_2fa_cache_set_get(self):
        v = VaultState()
        v.set_2fa_cache("totp", 0, True, 0)
        cached = v.get_2fa_cache()
        assert cached == ("totp", 0, True, 0)

    def test_2fa_cache_expired(self):
        v = VaultState()
        v._2fa_cache = ("totp", 0, True, 0, time.monotonic() - 1)  # already expired
        assert v.get_2fa_cache() is None

    def test_2fa_cache_expires_at_exact_boundary(self, monkeypatch):
        import api.app.vault_state as state_mod

        now = 1000.0
        monkeypatch.setattr(state_mod.time, "monotonic", lambda: now)
        v = VaultState()
        v._2fa_cache = ("totp", 0, True, 0, now)

        assert v.get_2fa_cache() is None

    def test_2fa_cache_invalidate(self):
        v = VaultState()
        v.set_2fa_cache("yubikey", 2, False, 0)
        v.invalidate_2fa_cache()
        assert v.get_2fa_cache() is None

    def test_2fa_cache_none_initially(self):
        v = VaultState()
        assert v.get_2fa_cache() is None

    def test_unseal_clears_2fa_cache(self):
        v = VaultState()
        v.set_2fa_cache("totp", 0, True, 0)
        v.unseal(
            {
                "hmac_key": os.urandom(32),
                "dek_key": os.urandom(32),
                "audit_key": os.urandom(32),
                "ha_wrap_key": os.urandom(32),
                "pki_wrap_key": os.urandom(32),
            }
        )
        assert v.get_2fa_cache() is None

    def test_seal_clears_2fa_cache(self):
        v = VaultState()
        v.unseal(
            {
                "hmac_key": os.urandom(32),
                "dek_key": os.urandom(32),
                "audit_key": os.urandom(32),
                "ha_wrap_key": os.urandom(32),
                "pki_wrap_key": os.urandom(32),
            }
        )
        v.set_2fa_cache("totp", 0, True, 0)
        v.seal()
        assert v.get_2fa_cache() is None
