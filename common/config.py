import json
import os
from pathlib import Path

HOST = "127.0.0.1"
AS_PORT = 8800
TGS_PORT = 8801
SERVICE_PORT = 8802

TICKET_LIFETIME = 600
CLOCK_SKEW = 300

PBKDF2_ITERATIONS = 100_000

KEY_MODES = ("aes128", "weak8")
KEY_MODE = os.environ.get("KRB_KEY_MODE", "aes128")
if KEY_MODE not in KEY_MODES:
    raise ValueError(f"KRB_KEY_MODE doit valoir l'un de {KEY_MODES}, pas {KEY_MODE!r}")

TGS_PRINCIPAL = "krbtgt"
SERVICES = ("mail",)
DEFAULT_CLIENT = "alice"
DEFAULT_SERVICE = "mail"

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
