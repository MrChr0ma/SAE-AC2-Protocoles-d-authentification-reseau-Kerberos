"""Paramètres partagés par tous les programmes du projet.

Modifier une valeur ici change le comportement de tout le monde :
prévenir le groupe avant (voir CONTRIBUTING.md).
"""

import json
import os
from pathlib import Path

# --- Réseau -----------------------------------------------------------------
HOST = "127.0.0.1"
AS_PORT = 8800
TGS_PORT = 8801
SERVICE_PORT = 8802

# --- Temps (en secondes) ----------------------------------------------------
# Durée de vie d'un TGT ou d'un ticket de service.
TICKET_LIFETIME = 600
# Écart d'horloge toléré entre le timestamp d'un authenticator et l'heure
# du serveur (5 minutes, comme la valeur par défaut des vrais KDC).
CLOCK_SKEW = 300

# --- Dérivation de la clé du client ------------------------------------------
PBKDF2_ITERATIONS = 100_000

# --- Taille des clés ----------------------------------------------------------
# "aes128" : vraies clés AES-128 aléatoires (128 bits d'entropie).
# "weak8"  : clés AES-128 valides mais tirées parmi 256 valeurs seulement
#            (8 bits d'entropie), pour montrer qu'elles se cassent par force brute.
# Se change sans toucher au code : KRB_KEY_MODE=weak8 python ...
KEY_MODES = ("aes128", "weak8")
KEY_MODE = os.environ.get("KRB_KEY_MODE", "aes128")
if KEY_MODE not in KEY_MODES:
    raise ValueError(f"KRB_KEY_MODE doit valoir l'un de {KEY_MODES}, pas {KEY_MODE!r}")

# --- Principaux (noms des identités) ----------------------------------------
# Nom du principal du TGS : c'est l'entrée de keys.json qui contient K_tgs
# (même nom que dans les vrais KDC).
TGS_PRINCIPAL = "krbtgt"
# Services que le TGS accepte de servir (chacun doit avoir sa clé dans keys.json).
SERVICES = ("mail",)
DEFAULT_CLIENT = "alice"
DEFAULT_SERVICE = "mail"

# --- Fichier des clés long terme ----------------------------------------------
# Généré par scripts/init_keys.py, à la racine du dépôt, jamais committé.
ROOT_DIR = Path(__file__).resolve().parent.parent
KEYS_FILE = Path(os.environ.get("KRB_KEYS_FILE", ROOT_DIR / "keys.json"))


def load_keys(path: Path | str = KEYS_FILE) -> dict[str, bytes]:
    """Charge keys.json et renvoie {nom_du_principal: clé en bytes}.

    Exemple : load_keys()["krbtgt"] -> K_tgs (16 octets).
    Lève FileNotFoundError avec un message clair si le fichier n'existe pas.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"{path} introuvable : lance d'abord "
            "`python scripts/init_keys.py --password <mot de passe d'alice>`"
        )
    with path.open(encoding="utf-8") as f:
        raw = json.load(f)
    return {name: bytes.fromhex(key_hex) for name, key_hex in raw.items()}
