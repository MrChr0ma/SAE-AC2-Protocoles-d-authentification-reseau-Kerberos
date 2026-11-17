"""Tests de common/crypto.py."""

import pytest

from common import config, crypto
from common.crypto import DecryptError, decrypt, derive_key, encrypt, new_session_key, weak_key

DATA = {"client": "alice", "k_c_tgs": "00" * 16, "exp": 1_800_000_000.5}


def test_aller_retour():
    key = new_session_key("aes128")
    blob = encrypt(key, DATA, "TGT")
    assert isinstance(blob, str)
    assert decrypt(key, blob, "TGT") == DATA


def test_mauvaise_cle():
    blob = encrypt(new_session_key("aes128"), DATA, "TGT")
    with pytest.raises(DecryptError):
        decrypt(new_session_key("aes128"), blob, "TGT")


def test_mauvais_aad():
    key = new_session_key("aes128")
    blob = encrypt(key, DATA, "TGT")
    with pytest.raises(DecryptError):
        decrypt(key, blob, "TICKET")


@pytest.mark.parametrize("position", [0, 12, -1])  # dans le nonce, le chiffré, le tag
def test_chiffre_modifie(position):
    key = new_session_key("aes128")
    raw = bytearray(bytes.fromhex(encrypt(key, DATA, "TGT")))
    raw[position] ^= 0x01
    with pytest.raises(DecryptError):
        decrypt(key, raw.hex(), "TGT")


@pytest.mark.parametrize("blob", ["pas de l'hex", "abcd", ""])
def test_blob_mal_forme(blob):
    with pytest.raises(DecryptError):
        decrypt(new_session_key("aes128"), blob, "TGT")


def test_aad_inconnu_refuse():
    with pytest.raises(ValueError):
        encrypt(new_session_key("aes128"), DATA, "N_IMPORTE_QUOI")


def test_chiffrements_differents():
    """Même clé, mêmes données : nonce différent, donc sortie différente."""
    key = new_session_key("aes128")
    blobs = {encrypt(key, DATA, "TGT") for _ in range(100)}
    assert len(blobs) == 100
    nonces = {b[: crypto.NONCE_SIZE * 2] for b in blobs}
    assert len(nonces) == 100


def test_derive_key_deterministe_et_depend_du_sel():
    k1 = derive_key("motdepasse", "alice")
    assert k1 == derive_key("motdepasse", "alice")
    assert len(k1) == 16
    assert k1 != derive_key("motdepasse", "bob")
    assert k1 != derive_key("autre", "alice")


def test_derive_key_utilisable_avec_aes():
    key = derive_key("motdepasse", "alice")
    assert decrypt(key, encrypt(key, DATA, "AS_REP"), "AS_REP") == DATA


def test_new_session_key_aes128():
    keys = {new_session_key("aes128") for _ in range(50)}
    assert all(len(k) == 16 for k in keys)
    assert len(keys) == 50


def test_new_session_key_mode_par_defaut(monkeypatch):
    monkeypatch.setattr(config, "KEY_MODE", "weak8")
    assert new_session_key() in {weak_key(n) for n in range(256)}


def test_weak_key():
    assert len(weak_key(0)) == 16
    assert len({weak_key(n) for n in range(256)}) == 256
    with pytest.raises(ValueError):
        weak_key(256)


def test_weak8_force_brute_en_256_essais_max():
    """En mode weak8, un attaquant retrouve la clé en au plus 256 essais."""
    secret = new_session_key("weak8")
    blob = encrypt(secret, DATA, "TICKET")

    found, tries = None, 0
    for n in range(256):
        tries += 1
        candidate = weak_key(n)
        try:
            decrypt(candidate, blob, "TICKET")
        except DecryptError:
            continue
        found = candidate
        break

    assert found == secret
    assert tries <= 256
