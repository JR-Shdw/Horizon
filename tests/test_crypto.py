"""Unit tests for cryptographic primitives - no database needed.

Covers all 5 crypto layers:
  1. Argon2id key derivation
  2. HKDF-SHA512 sub-key derivation
  3. XChaCha20-Poly1305 secret encryption
  4. AES-256-GCM DEK wrapping
  5. HMAC-SHA512 tokens + audit chain
Plus: TOTP, YubiKey HMAC-SHA1, token generation, DEK generation.
"""

import asyncio
import hashlib
import hmac
import os
import threading
import time

import pyotp
import pytest
from api.app import crypto as crypto_mod
from api.app.crypto import (
    ARGON2_MEMLIMIT,
    ARGON2_OPSLIMIT,
    ARGON2_SALTBYTES,
    MASTER_KEY_BYTES,
    XCHACHA_KEY_BYTES,
    XCHACHA_NONCE_BYTES,
    decrypt_dek,
    decrypt_secret,
    derive_keys,
    derive_master_key,
    derive_master_key_async,
    encrypt_dek,
    encrypt_secret,
    generate_dek,
    generate_salt,
    generate_token,
    generate_totp_secret,
    get_totp_uri,
    hmac_token,
    shamir_combine,
    shamir_split,
    sign_audit,
    totp_counter_for_code,
    verify_token,
    verify_totp,
    verify_yubikey_response,
)

# Layer 1, Argon2id


class TestArgon2id:
    def test_derive_master_key_length(self):
        salt = generate_salt()
        key = derive_master_key(b"password", salt)
        assert len(key) == MASTER_KEY_BYTES

    def test_derive_deterministic(self):
        """Same password + salt = same key."""
        salt = generate_salt()
        k1 = derive_master_key(b"test-password", salt)
        k2 = derive_master_key(b"test-password", salt)
        assert k1 == k2

    def test_derive_different_passwords(self):
        salt = generate_salt()
        k1 = derive_master_key(b"password-a", salt)
        k2 = derive_master_key(b"password-b", salt)
        assert k1 != k2

    def test_derive_different_salts(self):
        k1 = derive_master_key(b"password", generate_salt())
        k2 = derive_master_key(b"password", generate_salt())
        assert k1 != k2

    @pytest.mark.asyncio
    async def test_derive_async_matches_sync(self):
        """The off-loop wrapper yields the same key as the sync derivation."""
        salt = generate_salt()
        assert await derive_master_key_async(b"pw", salt) == derive_master_key(
            b"pw", salt
        )

    @pytest.mark.asyncio
    async def test_derive_async_keeps_loop_responsive(self, monkeypatch):
        """derive_master_key_async must not block the event loop.

        Stub Argon2 with a 300 ms *blocking* sleep (GIL is released inside a
        real to_thread call the same way time.sleep releases it). A 20 ms ticker
        running concurrently must keep ticking -> max stall well under the block.
        """
        monkeypatch.setattr(
            crypto_mod,
            "derive_master_key",
            lambda pw, salt: time.sleep(0.3) or b"\x00" * MASTER_KEY_BYTES,
        )

        gaps: list[float] = []
        stop = asyncio.Event()

        async def ticker():
            last = time.monotonic()
            while not stop.is_set():
                await asyncio.sleep(0.02)
                now = time.monotonic()
                gaps.append(now - last)
                last = now

        t = asyncio.create_task(ticker())
        await asyncio.sleep(0.02)
        key = await derive_master_key_async(b"pw", generate_salt())
        stop.set()
        await t

        assert key == b"\x00" * MASTER_KEY_BYTES
        # inline would stall ~300 ms; off-loop keeps ticks near the 20 ms cadence
        assert max(gaps) < 0.1, f"loop stalled {max(gaps) * 1000:.0f} ms"

    @pytest.mark.asyncio
    async def test_derive_async_concurrency_bounded_to_one(self, monkeypatch):
        """The Semaphore(1) must serialize concurrent Argon2 runs (256 MB each)
        so two /unseal requests can't allocate 2x256 MB at once."""
        active = 0
        max_active = 0

        def slow(pw, salt):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            time.sleep(0.15)
            active -= 1
            return b"\x00" * MASTER_KEY_BYTES

        monkeypatch.setattr(crypto_mod, "derive_master_key", slow)
        salt = generate_salt()
        await asyncio.gather(
            derive_master_key_async(b"a", salt),
            derive_master_key_async(b"b", salt),
            derive_master_key_async(b"c", salt),
        )
        assert max_active == 1, f"expected serialized, saw {max_active} concurrent"

    @pytest.mark.asyncio
    async def test_cancelled_derive_holds_slot_until_worker_finishes(self, monkeypatch):
        """Request cancellation must not defeat the Argon2 memory bound."""
        first_started = threading.Event()
        release_first = threading.Event()
        second_started = threading.Event()
        call_count = 0
        call_lock = threading.Lock()

        def controlled(pw, salt):
            nonlocal call_count
            with call_lock:
                call_count += 1
                call_number = call_count
            if call_number == 1:
                first_started.set()
                assert release_first.wait(timeout=2)
            else:
                second_started.set()
            return b"\x00" * MASTER_KEY_BYTES

        monkeypatch.setattr(crypto_mod, "derive_master_key", controlled)
        salt = generate_salt()
        first = asyncio.create_task(derive_master_key_async(b"a", salt))
        second = None
        try:
            assert await asyncio.to_thread(first_started.wait, 1)
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first

            second = asyncio.create_task(derive_master_key_async(b"b", salt))
            await asyncio.sleep(0.05)
            assert not second_started.is_set()

            release_first.set()
            assert await second == b"\x00" * MASTER_KEY_BYTES
            assert second_started.is_set()
        finally:
            release_first.set()
            if second is not None and not second.done():
                await second

    def test_salt_length(self):
        salt = generate_salt()
        assert len(salt) == ARGON2_SALTBYTES

    def test_constants(self):
        assert ARGON2_OPSLIMIT >= 3
        assert ARGON2_MEMLIMIT >= 256 * 1024 * 1024
        assert MASTER_KEY_BYTES == 32


# Layer 2, HKDF-SHA512


class TestHKDF:
    def test_derive_keys_returns_all(self):
        master = os.urandom(32)
        keys = derive_keys(master)
        assert "hmac_key" in keys
        assert "dek_key" in keys
        assert "audit_key" in keys

    def test_derive_keys_length(self):
        master = os.urandom(32)
        keys = derive_keys(master)
        for name, key in keys.items():
            assert len(key) == 32, f"{name} should be 32 bytes"

    def test_derive_keys_are_wipeable(self):
        master = bytearray(os.urandom(32))
        keys = derive_keys(master)
        assert all(isinstance(key, bytearray) for key in keys.values())
        keys.wipe()
        assert all(key == bytearray(32) for key in keys.values())

    def test_derive_keys_deterministic(self):
        master = os.urandom(32)
        k1 = derive_keys(master)
        k2 = derive_keys(master)
        assert k1["hmac_key"] == k2["hmac_key"]
        assert k1["dek_key"] == k2["dek_key"]
        assert k1["audit_key"] == k2["audit_key"]

    def test_derive_keys_unique(self):
        """Each sub-key must be different from the others."""
        master = os.urandom(32)
        keys = derive_keys(master)
        assert keys["hmac_key"] != keys["dek_key"]
        assert keys["hmac_key"] != keys["audit_key"]
        assert keys["dek_key"] != keys["audit_key"]

    def test_derive_keys_different_master(self):
        k1 = derive_keys(os.urandom(32))
        k2 = derive_keys(os.urandom(32))
        assert k1["hmac_key"] != k2["hmac_key"]

    @pytest.mark.parametrize("version", [0, -1])
    def test_derive_keys_rejects_non_positive_dek_version(self, version):
        with pytest.raises(ValueError, match="at least 1"):
            derive_keys(os.urandom(32), dek_key_version=version)

    @pytest.mark.parametrize("version", [True, 1.0, "1"])
    def test_derive_keys_rejects_non_integer_dek_version(self, version):
        with pytest.raises(TypeError, match="must be an integer"):
            derive_keys(os.urandom(32), dek_key_version=version)


# Layer 3, XChaCha20-Poly1305


_AAD = b"test-aad"
_DEK_AAD = b"test-dek-aad"


class TestXChaCha20:
    def test_encrypt_decrypt_roundtrip(self):
        dek = generate_dek()
        plaintext = b"super secret data"
        ct, nonce = encrypt_secret(plaintext, dek, _AAD)
        result = decrypt_secret(ct, nonce, dek, _AAD)
        assert result == plaintext

    def test_ciphertext_differs_from_plaintext(self):
        dek = generate_dek()
        plaintext = b"my secret"
        ct, _ = encrypt_secret(plaintext, dek, _AAD)
        assert ct != plaintext

    def test_nonce_is_correct_length(self):
        dek = generate_dek()
        _, nonce = encrypt_secret(b"data", dek, _AAD)
        assert len(nonce) == XCHACHA_NONCE_BYTES

    def test_different_nonces_each_call(self):
        dek = generate_dek()
        _, n1 = encrypt_secret(b"data", dek, _AAD)
        _, n2 = encrypt_secret(b"data", dek, _AAD)
        assert n1 != n2

    def test_wrong_key_fails(self):
        dek1 = generate_dek()
        dek2 = generate_dek()
        ct, nonce = encrypt_secret(b"secret", dek1, _AAD)
        with pytest.raises(Exception):
            decrypt_secret(ct, nonce, dek2, _AAD)

    def test_tampered_ciphertext_fails(self):
        dek = generate_dek()
        ct, nonce = encrypt_secret(b"secret", dek, _AAD)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(Exception):
            decrypt_secret(bytes(tampered), nonce, dek, _AAD)

    def test_empty_plaintext(self):
        dek = generate_dek()
        ct, nonce = encrypt_secret(b"", dek, _AAD)
        result = decrypt_secret(ct, nonce, dek, _AAD)
        assert result == b""

    def test_large_plaintext(self):
        dek = generate_dek()
        plaintext = os.urandom(1024 * 100)  # 100 KB
        ct, nonce = encrypt_secret(plaintext, dek, _AAD)
        result = decrypt_secret(ct, nonce, dek, _AAD)
        assert result == plaintext


# Layer 4, AES-256-GCM (DEK wrapping)


class TestAESGCM:
    def test_wrap_unwrap_roundtrip(self):
        dek = generate_dek()
        dek_key = os.urandom(32)
        encrypted, nonce = encrypt_dek(dek, dek_key, None, _DEK_AAD)
        result = decrypt_dek(encrypted, nonce, dek_key, None, _DEK_AAD)
        assert result == dek

    def test_wrong_key_fails(self):
        dek = generate_dek()
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        encrypted, nonce = encrypt_dek(dek, key1, None, _DEK_AAD)
        with pytest.raises(Exception):
            decrypt_dek(encrypted, nonce, key2, None, _DEK_AAD)

    def test_tampered_encrypted_dek_fails(self):
        dek = generate_dek()
        dek_key = os.urandom(32)
        encrypted, nonce = encrypt_dek(dek, dek_key, None, _DEK_AAD)
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        with pytest.raises(Exception):
            decrypt_dek(bytes(tampered), nonce, dek_key, None, _DEK_AAD)

    def test_nonce_12_bytes(self):
        dek = generate_dek()
        _, nonce = encrypt_dek(dek, os.urandom(32), None, _DEK_AAD)
        assert len(nonce) == 12

    def test_cached_aesgcm_roundtrip(self):
        dek = generate_dek()
        aesgcm = crypto_mod.AESGCM(os.urandom(32))
        encrypted, nonce = encrypt_dek(dek, None, aesgcm, _DEK_AAD)
        assert decrypt_dek(encrypted, nonce, None, aesgcm, _DEK_AAD) == dek

    @pytest.mark.parametrize("key_size", [16, 24])
    def test_rejects_non_256_bit_raw_keys(self, key_size):
        dek = generate_dek()
        invalid_key = os.urandom(key_size)
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            encrypt_dek(dek, invalid_key, None, _DEK_AAD)

        encrypted, nonce = encrypt_dek(dek, os.urandom(32), None, _DEK_AAD)
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            decrypt_dek(encrypted, nonce, invalid_key, None, _DEK_AAD)

    @pytest.mark.parametrize(
        ("dek_key", "aesgcm"),
        [
            (None, None),
            (b"\x00" * 32, crypto_mod.AESGCM(b"\x01" * 32)),
        ],
    )
    def test_rejects_ambiguous_key_sources(self, dek_key, aesgcm):
        with pytest.raises(ValueError, match="exactly one"):
            encrypt_dek(generate_dek(), dek_key, aesgcm, _DEK_AAD)

        valid_key = os.urandom(32)
        encrypted, nonce = encrypt_dek(
            generate_dek(),
            valid_key,
            None,
            _DEK_AAD,
        )
        with pytest.raises(ValueError, match="exactly one"):
            decrypt_dek(encrypted, nonce, dek_key, aesgcm, _DEK_AAD)


# Review #8, AAD binds ciphertext to row identity


class TestAADBinding:
    def test_secret_aad_helper(self):
        from api.app.crypto import secret_aad as _secret_aad

        assert _secret_aad("api-key", "default").startswith(b"secret:v2:")
        assert _secret_aad("a", "b") != _secret_aad("b", "a")
        assert _secret_aad("a:b", "c") != _secret_aad("a", "b:c")
        assert _secret_aad("api-key", "default", version=1) == b"secret:api-key:default"

    def test_secret_aad_rejects_unknown_version(self):
        from api.app.crypto import secret_aad as _secret_aad

        for version in (True, 3, "2"):
            with pytest.raises(ValueError, match="Unsupported"):
                _secret_aad("api-key", "default", version=version)

    def test_dek_aad_helper(self):
        from api.app.crypto import dek_aad as _dek_aad

        assert _dek_aad("abc-123") == b"dek:abc-123"
        assert _dek_aad("x") != _dek_aad("y")

    def test_decrypt_secret_wrong_aad_fails(self):
        dek = generate_dek()
        ct, nonce = encrypt_secret(b"plaintext", dek, b"aad-A")
        with pytest.raises(Exception):
            decrypt_secret(ct, nonce, dek, b"aad-B")

    def test_decrypt_dek_wrong_aad_fails(self):
        dek = generate_dek()
        dek_key = os.urandom(32)
        encrypted, nonce = encrypt_dek(dek, dek_key, None, b"aad-A")
        with pytest.raises(Exception):
            decrypt_dek(encrypted, nonce, dek_key, None, b"aad-B")

    def test_secret_swap_between_rows_fails(self):
        """Simulate DB-row substitution: ciphertext A encrypted with AAD A
        cannot be decrypted with AAD B even with the right DEK."""
        from api.app.crypto import secret_aad as _secret_aad

        dek = generate_dek()
        aad_a = _secret_aad("secret-a", "default")
        aad_b = _secret_aad("secret-b", "default")
        ct_a, nonce_a = encrypt_secret(b"value-a", dek, aad_a)
        # Attacker swaps row B's metadata to point to row A's ciphertext -
        # decryption tries aad_b -> fails.
        with pytest.raises(Exception):
            decrypt_secret(ct_a, nonce_a, dek, aad_b)
        # Sanity: original AAD still works
        assert decrypt_secret(ct_a, nonce_a, dek, aad_a) == b"value-a"


# Layer 5, HMAC-SHA512


class TestHMAC:
    def test_hmac_token_deterministic(self):
        key = os.urandom(32)
        h1 = hmac_token(key, "rh_test123")
        h2 = hmac_token(key, "rh_test123")
        assert h1 == h2

    def test_hmac_token_length(self):
        key = os.urandom(32)
        h = hmac_token(key, "rh_test")
        assert len(h) == 128  # SHA-512 hex = 128 chars

    def test_different_keys_different_hashes(self):
        h1 = hmac_token(os.urandom(32), "rh_test")
        h2 = hmac_token(os.urandom(32), "rh_test")
        assert h1 != h2

    def test_different_tokens_different_hashes(self):
        key = os.urandom(32)
        h1 = hmac_token(key, "rh_token1")
        h2 = hmac_token(key, "rh_token2")
        assert h1 != h2

    def test_verify_token_valid(self):
        key = os.urandom(32)
        token = "rh_test123"
        h = hmac_token(key, token)
        assert verify_token(key, token, h) is True

    def test_verify_token_invalid(self):
        key = os.urandom(32)
        assert verify_token(key, "rh_test", "bad_hash") is False

    def test_verify_token_wrong_key(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        token = "rh_test"
        h = hmac_token(key1, token)
        assert verify_token(key2, token, h) is False


# Audit chain signatures


class TestAuditChain:
    def test_sign_audit_deterministic(self):
        key = os.urandom(32)
        s1 = sign_audit(key, "admin|create|secret1|{}")
        s2 = sign_audit(key, "admin|create|secret1|{}")
        assert s1 == s2

    def test_sign_audit_chain_integrity(self):
        """Verify chained signatures - changing entry N breaks N+1."""
        key = os.urandom(32)
        sig0 = sign_audit(key, "actor|action1|target1|{}", "")
        sig1 = sign_audit(key, "actor|action2|target2|{}", sig0)
        sig2 = sign_audit(key, "actor|action3|target3|{}", sig1)

        # Verify chain is valid
        check0 = sign_audit(key, "actor|action1|target1|{}", "")
        assert check0 == sig0
        check1 = sign_audit(key, "actor|action2|target2|{}", check0)
        assert check1 == sig1
        check2 = sign_audit(key, "actor|action3|target3|{}", check1)
        assert check2 == sig2

    def test_sign_audit_tamper_detection(self):
        """Modifying a payload breaks the chain from that point."""
        key = os.urandom(32)
        sig0 = sign_audit(key, "actor|create|secret1|{}", "")
        sig1 = sign_audit(key, "actor|read|secret1|{}", sig0)

        # Tampered entry 0 produces different sig
        tampered_sig0 = sign_audit(key, "actor|DELETE|secret1|{}", "")
        assert tampered_sig0 != sig0

        # Chain from tampered sig0 != original sig1
        tampered_sig1 = sign_audit(key, "actor|read|secret1|{}", tampered_sig0)
        assert tampered_sig1 != sig1

    def test_sign_audit_deletion_detection(self):
        """Deleting an entry breaks the chain."""
        key = os.urandom(32)
        sig0 = sign_audit(key, "entry0", "")
        sig1 = sign_audit(key, "entry1", sig0)
        sig2 = sign_audit(key, "entry2", sig1)

        # If entry1 is deleted, sig2 would be recomputed from sig0
        fake_sig2 = sign_audit(key, "entry2", sig0)
        assert fake_sig2 != sig2


# Token generation


class TestTokenGeneration:
    def test_token_prefix(self):
        token = generate_token()
        assert token.startswith("rh_")

    def test_token_length(self):
        token = generate_token()
        assert len(token) > 40  # rh_ + 43 base64 chars

    def test_tokens_unique(self):
        t1 = generate_token()
        t2 = generate_token()
        assert t1 != t2

    def test_dek_length(self):
        dek = generate_dek()
        assert len(dek) == XCHACHA_KEY_BYTES


# TOTP


class TestTOTP:
    def test_generate_totp_secret(self):
        secret = generate_totp_secret()
        assert len(secret) == 32  # base32 encoded

    def test_verify_totp_valid(self):
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert verify_totp(secret, code) is True

    def test_verify_totp_invalid(self):
        secret = generate_totp_secret()
        assert verify_totp(secret, "000000") is False

    def test_totp_counter_matches_skew_window(self):
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        timestamp = 1_800_000_000
        current = int(timestamp) // totp.interval

        for offset in (-1, 0, 1):
            assert (
                totp_counter_for_code(
                    secret,
                    totp.generate_otp(current + offset),
                    at_time=timestamp,
                )
                == current + offset
            )

    def test_totp_counter_rejects_outside_window_and_malformed_code(self):
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        timestamp = 1_800_000_000
        current = int(timestamp) // totp.interval

        assert (
            totp_counter_for_code(
                secret,
                totp.generate_otp(current + 2),
                at_time=timestamp,
            )
            is None
        )
        assert totp_counter_for_code(secret, "１２３４５６", at_time=timestamp) is None

    def test_get_totp_uri(self):
        secret = generate_totp_secret()
        uri = get_totp_uri(secret)
        assert uri.startswith("otpauth://totp/")
        assert "rhorizon" in uri

    def test_get_totp_uri_custom_name(self):
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, name="admin@vault")
        assert "admin%40vault" in uri or "admin@vault" in uri


# YubiKey HMAC-SHA1


class TestYubiKey:
    def test_verify_valid_response(self):
        secret = os.urandom(20)
        challenge = os.urandom(32)
        response = hmac.new(secret, challenge, hashlib.sha1).digest()
        assert verify_yubikey_response(secret, challenge, response) is True

    def test_verify_invalid_response(self):
        secret = os.urandom(20)
        challenge = os.urandom(32)
        bad_response = os.urandom(20)
        assert verify_yubikey_response(secret, challenge, bad_response) is False

    def test_verify_wrong_secret(self):
        secret1 = os.urandom(20)
        secret2 = os.urandom(20)
        challenge = os.urandom(32)
        response = hmac.new(secret1, challenge, hashlib.sha1).digest()
        assert verify_yubikey_response(secret2, challenge, response) is False

    def test_verify_wrong_challenge(self):
        secret = os.urandom(20)
        challenge1 = os.urandom(32)
        challenge2 = os.urandom(32)
        response = hmac.new(secret, challenge1, hashlib.sha1).digest()
        assert verify_yubikey_response(secret, challenge2, response) is False


# Double envelope, full stack test


class TestDoubleEnvelope:
    def test_full_stack_encrypt_decrypt(self):
        """Simulate the complete vault encryption flow."""
        # 1. Derive master key
        password = b"test-master-password"
        salt = generate_salt()
        master_key = derive_master_key(password, salt)

        # 2. Derive sub-keys
        keys = derive_keys(master_key)

        # 3. Generate DEK, wrap with dek_key
        dek = generate_dek()
        encrypted_dek, dek_nonce = encrypt_dek(dek, keys["dek_key"], None, _DEK_AAD)

        # 4. Encrypt secret with DEK
        secret_value = b"my-database-password-123!"
        ciphertext, secret_nonce = encrypt_secret(secret_value, dek, _AAD)

        # 5. Decrypt (reverse)
        recovered_dek = decrypt_dek(
            encrypted_dek, dek_nonce, keys["dek_key"], None, _DEK_AAD
        )
        assert recovered_dek == dek

        recovered_secret = decrypt_secret(ciphertext, secret_nonce, recovered_dek, _AAD)
        assert recovered_secret == secret_value

    def test_full_stack_dek_rotation(self):
        """Re-encrypt secret with new DEK, value unchanged."""
        password = b"test-password"
        salt = generate_salt()
        master_key = derive_master_key(password, salt)
        keys = derive_keys(master_key)

        # Original encryption
        dek1 = generate_dek()
        encrypted_dek1, dek1_nonce = encrypt_dek(dek1, keys["dek_key"], None, _DEK_AAD)
        secret = b"rotate-me"
        ct1, nonce1 = encrypt_secret(secret, dek1, _AAD)

        # Decrypt with old DEK
        recovered_dek1 = decrypt_dek(
            encrypted_dek1, dek1_nonce, keys["dek_key"], None, _DEK_AAD
        )
        plaintext = decrypt_secret(ct1, nonce1, recovered_dek1, _AAD)
        assert plaintext == secret

        # Re-encrypt with new DEK
        dek2 = generate_dek()
        encrypted_dek2, dek2_nonce = encrypt_dek(dek2, keys["dek_key"], None, _DEK_AAD)
        ct2, nonce2 = encrypt_secret(plaintext, dek2, _AAD)

        # Verify new encryption works
        recovered_dek2 = decrypt_dek(
            encrypted_dek2, dek2_nonce, keys["dek_key"], None, _DEK_AAD
        )
        result = decrypt_secret(ct2, nonce2, recovered_dek2, _AAD)
        assert result == secret
        assert dek1 != dek2
        assert ct1 != ct2

    def test_full_stack_wrong_password(self):
        """Wrong password derives different keys, decryption fails."""
        salt = generate_salt()
        master_key = derive_master_key(b"correct-password", salt)
        keys = derive_keys(master_key)

        dek = generate_dek()
        encrypted_dek, dek_nonce = encrypt_dek(dek, keys["dek_key"], None, _DEK_AAD)

        # Wrong password
        wrong_master = derive_master_key(b"wrong-password", salt)
        wrong_keys = derive_keys(wrong_master)

        with pytest.raises(Exception):
            decrypt_dek(encrypted_dek, dek_nonce, wrong_keys["dek_key"], None, _DEK_AAD)


# Shamir Secret Sharing


class TestShamir:
    def test_split_and_combine_2_of_3(self):
        """Basic 2-of-3 split and reconstruct."""
        secret = os.urandom(32)
        shares = shamir_split(secret, 2, 3)
        assert len(shares) == 3
        # Any 2 shares should reconstruct
        assert shamir_combine(shares[:2]) == secret
        assert shamir_combine(shares[1:]) == secret
        assert shamir_combine([shares[0], shares[2]]) == secret

    def test_split_and_combine_3_of_5(self):
        """3-of-5 split - any 3 shares work."""
        secret = os.urandom(96)  # 96 bytes like vault key material
        shares = shamir_split(secret, 3, 5)
        assert len(shares) == 5
        assert shamir_combine([shares[0], shares[2], shares[4]]) == secret
        assert shamir_combine([shares[1], shares[3], shares[4]]) == secret

    def test_insufficient_shares_wrong_result(self):
        """Fewer than threshold shares produce wrong result."""
        secret = os.urandom(32)
        shares = shamir_split(secret, 3, 5)
        # 2 shares when threshold is 3, reconstructs but incorrectly
        result = shamir_combine([shares[0], shares[1]])
        assert result != secret

    def test_share_format(self):
        """Each share is x-byte + secret_len y-bytes."""
        secret = os.urandom(16)
        shares = shamir_split(secret, 2, 3)
        for i, share in enumerate(shares):
            assert len(share) == 17  # 1 + 16
            assert share[0] == i + 1  # x-coordinates are 1-indexed

    def test_threshold_validation(self):
        with pytest.raises(ValueError, match="Threshold must be >= 2"):
            shamir_split(b"secret", 1, 3)

    def test_total_validation(self):
        with pytest.raises(ValueError, match="Total shares must be >= threshold"):
            shamir_split(b"secret", 3, 2)

    def test_max_shares_validation(self):
        shares = shamir_split(b"secret", 2, 255)
        assert len(shares) == 255
        assert shares[-1][0] == 255
        with pytest.raises(ValueError, match="Maximum 255"):
            shamir_split(b"secret", 2, 256)

    def test_split_rejects_empty_secret(self):
        with pytest.raises(ValueError, match="non-empty"):
            shamir_split(b"", 2, 3)

    def test_combine_minimum_shares(self):
        with pytest.raises(ValueError, match="need at least 2"):
            shamir_combine([b"\x01secret"])

    def test_combine_duplicate_indices(self):
        with pytest.raises(ValueError, match="duplicate share"):
            shamir_combine([b"\x01abc", b"\x01xyz"])

    def test_combine_zero_index_rejected(self):
        with pytest.raises(ValueError, match="index zero"):
            shamir_combine([b"\x00abc", b"\x02xyz"])

    def test_combine_empty_share_rejected(self):
        with pytest.raises(ValueError, match="x-coordinate and payload"):
            shamir_combine([b"", b"\x02abc"])

    def test_combine_x_only_share_rejected(self):
        with pytest.raises(ValueError, match="x-coordinate and payload"):
            shamir_combine([b"\x01", b"\x02"])

    def test_vault_key_material_roundtrip(self):
        """Simulate vault Shamir: split 3x32 byte keys, reconstruct."""
        keys = {
            "hmac_key": os.urandom(32),
            "dek_key": os.urandom(32),
            "audit_key": os.urandom(32),
        }
        key_material = keys["hmac_key"] + keys["dek_key"] + keys["audit_key"]
        assert len(key_material) == 96

        shares = shamir_split(key_material, 3, 5)
        recovered = shamir_combine([shares[0], shares[2], shares[4]])
        assert recovered == key_material

        # Split back into individual keys
        assert recovered[:32] == keys["hmac_key"]
        assert recovered[32:64] == keys["dek_key"]
        assert recovered[64:96] == keys["audit_key"]


def test_xchacha20poly1305_ietf_draft_kat():
    """draft-irtf-cfrg-xchacha20poly1305-03 A.3 vector -- supply-chain tripwire
    for the primary XChaCha20-Poly1305 secret-encryption path (libsodium)."""
    import nacl.bindings as nb

    pt = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only "
        b"one tip for the future, sunscreen would be it."
    )
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    ct = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, aad, nonce, key)
    expected = bytes.fromhex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780a"
        "cf49"
    )
    assert ct == expected


def test_argon2id_libsodium_tripwire():
    """libsodium Argon2id frozen-output tripwire. The high-level crypto_pwhash
    API can't take RFC 9106's secret/AD (that KAT lives on the Rust argon2 crate,
    backup_context.rs); this pins a fixed libsodium output to catch a swapped or
    corrupted libsodium on the primary master-key derivation path."""
    import nacl.bindings as nb

    out = nb.crypto_pwhash_alg(
        outlen=32,
        passwd=b"rhorizon-kat",
        salt=bytes(16),
        opslimit=2,
        memlimit=8 * 1024 * 1024,
        alg=nb.crypto_pwhash_ALG_ARGON2ID13,
    )
    assert (
        out.hex() == "0bbb7d3c64dcaebf2ca7cfea71c01759a990c95ee79b1f956306ac70a51d0d6b"
    )
