import math
import threading
import time

from common import config
from common.crypto import DecryptError, decrypt, encrypt, new_session_key
from common.net import error, log, serve

NAME = "TGS"

replay_cache: dict[tuple[str, float], float] = {}
cache_lock = threading.Lock()


def est_nombre(valeur) -> bool:
    """Vrai si valeur est un nombre fini utilisable comme date (booléen, NaN et infini refusés)."""
    if not isinstance(valeur, (int, float)) or isinstance(valeur, bool):
        return False
    try:
        return math.isfinite(float(valeur))
    except OverflowError:
        return False


def lire_cle(part: dict, nom: str) -> bytes | None:
    """Lit une clé de session de 16 octets écrite en hexadécimal, ou renvoie None."""
    valeur = part.get(nom)
    if not isinstance(valeur, str):
        return None
    try:
        cle = bytes.fromhex(valeur)
    except ValueError:
        return None
    if len(cle) != 16:
        return None
    return cle


def deja_vu(client: str, ts: float, maintenant: float) -> bool:
    """Enregistre l'authenticator (client, ts) et renvoie True s'il avait déjà été reçu.

    Une entrée est gardée deux fois la fenêtre CLOCK_SKEW : passé ce délai, le
    contrôle du timestamp suffit à refuser un rejeu, même si deux requêtes se croisent.
    """
    with cache_lock:
        for cle, oubli in list(replay_cache.items()):
            if oubli < maintenant:
                del replay_cache[cle]
        if (client, ts) in replay_cache:
            return True
        replay_cache[(client, ts)] = ts + 2 * config.CLOCK_SKEW
        return False


def handle_request(msg: dict, keys: dict[str, bytes]) -> dict:
    """Vérifie un TGS_REQ et renvoie un TGS_REP, ou un ERROR au premier contrôle qui échoue."""
    if (
        msg.get("type") != "TGS_REQ"
        or not isinstance(msg.get("tgt"), str)
        or not isinstance(msg.get("auth"), str)
        or not isinstance(msg.get("service"), str)
    ):
        return error("requête invalide")

    service = msg["service"]
    if service not in config.SERVICES or service not in keys:
        return error("service inconnu")

    try:
        tgt = decrypt(keys[config.TGS_PRINCIPAL], msg["tgt"], "TGT")
    except DecryptError:
        return error("TGT invalide")

    client = tgt.get("client")
    k_c_tgs = lire_cle(tgt, "k_c_tgs")
    if not isinstance(client, str) or k_c_tgs is None or not est_nombre(tgt.get("exp")):
        return error("TGT invalide")

    maintenant = time.time()
    if maintenant >= tgt["exp"]:
        return error("TGT expiré")

    try:
        auth = decrypt(k_c_tgs, msg["auth"], "TGS_AUTH")
    except DecryptError:
        return error("authenticator invalide")

    if not est_nombre(auth.get("ts")):
        return error("authenticator invalide")

    if auth.get("client") != client:
        return error("client de l'authenticator différent de celui du TGT")

    if abs(maintenant - auth["ts"]) > config.CLOCK_SKEW:
        return error("timestamp hors de la fenêtre autorisée")

    if deja_vu(client, auth["ts"], maintenant):
        return error("authenticator déjà utilisé (rejeu)")

    k_c_service = new_session_key().hex()
    exp = min(maintenant + config.TICKET_LIFETIME, tgt["exp"])
    enc_part = encrypt(k_c_tgs, {"k_c_service": k_c_service, "exp": exp}, "TGS_REP")
    ticket = encrypt(
        keys[service],
        {"client": client, "k_c_service": k_c_service, "exp": exp},
        "TICKET",
    )

    log(NAME, f"ticket délivré à {client} pour {service}")
    return {"type": "TGS_REP", "enc_part": enc_part, "ticket": ticket}


def main() -> None:
    """Charge les clés long terme et lance le TGS sur son port."""
    keys = config.load_keys()
    serve(config.HOST, config.TGS_PORT, lambda msg: handle_request(msg, keys), NAME)


if __name__ == "__main__":
    main()
