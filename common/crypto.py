"""Primitives cryptographiques du projet : dérivation de clé et AES-GCM.

Tout le chiffrement du protocole passe par encrypt() et decrypt().
Personne ne doit appeler AESGCM directement ailleurs dans le code.
"""

import hashlib
import json
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import config

KEY_SIZE = 16    # octets, AES-128
NONCE_SIZE = 12  # octets, taille recommandée pour GCM
TAG_SIZE = 16    # octets, ajouté par AESGCM à la fin du chiffré

# Valeurs autorisées pour le paramètre aad (une par rôle de chiffré).
AAD_VALUES = ("AS_REP", "TGT", "TGS_AUTH", "TGS_REP", "TICKET", "AP_AUTH", "AP_REP")


class DecryptError(Exception):
    """Le déchiffrement a échoué.

    Causes possibles : mauvaise clé, chiffré modifié, mauvais aad,
    ou blob mal formé. On ne distingue pas volontairement ces cas :
    AES-GCM ne dit pas pourquoi le tag est invalide, seulement qu'il l'est.
    """


def derive_key(password: str, salt: str) -> bytes:
    """Dérive une clé AES-128 (16 octets) depuis un mot de passe.

    PBKDF2-HMAC-SHA256 avec config.PBKDF2_ITERATIONS itérations.
    Le sel est le nom du principal (ex. "alice"), comme dans Kerberos :
    deux utilisateurs avec le même mot de passe n'ont pas la même clé.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        config.PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,
    )


def weak_key(n: int) -> bytes:
    """Clé AES-128 valide fabriquée à partir d'un octet n (0 à 255).

    AES-GCM n'accepte que des clés de 128, 192 ou 256 bits : on ne peut pas
    lui donner une clé de 8 bits. On « étire » donc n avec SHA-256. La clé
    obtenue fait bien 16 octets, mais il n'en existe que 256 différentes :
    un attaquant les essaie toutes en une fraction de seconde.
    """
    if not 0 <= n <= 255:
        raise ValueError("n doit être compris entre 0 et 255")
    return hashlib.sha256(bytes([n])).digest()[:KEY_SIZE]


def new_session_key(mode: str | None = None) -> bytes:
    """Génère une nouvelle clé aléatoire (clé de session ou clé de service).

    mode vaut config.KEY_MODE par défaut ("aes128" ou "weak8").
    """
    mode = mode or config.KEY_MODE
    if mode == "aes128":
        return AESGCM.generate_key(bit_length=128)
    if mode == "weak8":
        return weak_key(secrets.randbelow(256))
    raise ValueError(f"mode de clé inconnu : {mode!r}")


def encrypt(key: bytes, data: dict, aad: str) -> str:
    """Chiffre le dictionnaire data avec AES-GCM et renvoie une chaîne hex.

    Format de la sortie : hex(nonce (12 octets) + chiffré + tag (16 octets)).

    aad (« additional authenticated data ») n'est pas chiffré mais il est
    authentifié : decrypt() échoue si on ne lui donne pas exactement le même.
    On y met le rôle du chiffré ("TGT", "TICKET", ...) pour qu'un attaquant
    ne puisse pas présenter un chiffré à la place d'un autre.

    Le nonce : un nouveau nonce aléatoire de 12 octets est tiré À CHAQUE appel
    avec os.urandom. Jamais de nonce fixe, jamais de compteur remis à zéro.
    Pourquoi : GCM chiffre en faisant un XOR entre le message et un flux
    pseudo-aléatoire qui ne dépend que de (clé, nonce). Si deux messages sont
    chiffrés avec la même clé et le même nonce :
      - C1 XOR C2 = M1 XOR M2 : connaître un message révèle l'autre ;
      - pire, les deux tags permettent de retrouver la clé d'authentification
        H, et donc de fabriquer des chiffrés falsifiés acceptés comme valides.
    Avec 96 bits aléatoires, la probabilité d'une collision reste
    négligeable tant qu'on chiffre beaucoup moins de 2^32 messages par clé.
    """
    if aad not in AAD_VALUES:
        raise ValueError(f"aad inconnu : {aad!r} (valeurs possibles : {AAD_VALUES})")
    plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad.encode("utf-8"))
    return (nonce + ciphertext).hex()


def decrypt(key: bytes, blob: str, aad: str) -> dict:
    """Déchiffre un blob produit par encrypt() et renvoie le dictionnaire.

    Lève DecryptError si la clé est mauvaise, si le blob a été modifié,
    si l'aad ne correspond pas, ou si le blob est mal formé.
    """
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
    except ValueError as exc:  # clé de mauvaise taille
        raise DecryptError(f"clé invalide : {exc}") from exc
    try:
        data = json.loads(plaintext)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecryptError("le contenu déchiffré n'est pas du JSON") from exc
    if not isinstance(data, dict):
        raise DecryptError("le contenu déchiffré n'est pas un dictionnaire")
    return data
