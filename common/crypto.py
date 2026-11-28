import hashlib
import json
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import config

KEY_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16

AAD_VALUES = ("AS_REP", "TGT", "TGS_AUTH", "TGS_REP", "TICKET", "AP_AUTH", "AP_REP")


class DecryptError(Exception):
    """Déchiffrement impossible : mauvaise clé, mauvais aad, données modifiées ou blob mal formé."""


def derive_key(password: str, salt: str) -> bytes:
    """Dérive une clé AES-128 du mot de passe avec PBKDF2-HMAC-SHA256, le sel étant le nom du principal."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        config.PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,
    )


def weak_key(n: int) -> bytes:
    """Fabrique une clé AES-128 à partir d'un seul octet n : seulement 256 clés possibles (mode weak8)."""
    if not 0 <= n <= 255:
        raise ValueError("n doit être compris entre 0 et 255")
    return hashlib.sha256(bytes([n])).digest()[:KEY_SIZE]


def new_session_key(mode: str | None = None) -> bytes:
    """Génère une clé aléatoire de 16 octets, faible si le mode est weak8."""
    mode = mode or config.KEY_MODE
    if mode == "aes128":
        return AESGCM.generate_key(bit_length=128)
    if mode == "weak8":
        return weak_key(secrets.randbelow(256))
    raise ValueError(f"mode de clé inconnu : {mode!r}")


def encrypt(key: bytes, data: dict, aad: str) -> str:
    """Chiffre data (JSON) avec AES-GCM et renvoie nonce + chiffré + tag en hexadécimal.

    Un nouveau nonce aléatoire est tiré à chaque appel : réutiliser un nonce avec
    la même clé permettrait de retrouver les messages et de forger des chiffrés.
    aad indique le rôle du message, il doit être le même au déchiffrement.
    """
    if aad not in AAD_VALUES:
        raise ValueError(f"aad inconnu : {aad!r} (valeurs possibles : {AAD_VALUES})")
    plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad.encode("utf-8"))
    return (nonce + ciphertext).hex()


def decrypt(key: bytes, blob: str, aad: str) -> dict:
    """Déchiffre un blob produit par encrypt et renvoie le dictionnaire, ou lève DecryptError."""
    try:
        raw = bytes.fromhex(blob)
    except (TypeError, ValueError) as exc:
        raise DecryptError("blob mal formé (pas de l'hexadécimal)") from exc
    if len(raw) < NONCE_SIZE + TAG_SIZE:
        raise DecryptError("blob trop court")
    nonce, ciphertext = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad.encode("utf-8"))
    except InvalidTag as exc:
        raise DecryptError("tag invalide : mauvaise clé, mauvais aad ou données modifiées") from exc
    except ValueError as exc:
        raise DecryptError(f"clé invalide : {exc}") from exc
    try:
        data = json.loads(plaintext)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecryptError("le contenu déchiffré n'est pas du JSON") from exc
    if not isinstance(data, dict):
        raise DecryptError("le contenu déchiffré n'est pas un dictionnaire")
    return data
