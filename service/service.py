"""Partie 4 : le service (ici « mail »), troisième échange du protocole.

Rôle : le client présente le ticket de service et un authenticator. Le service :
  - ouvre le ticket avec sa propre clé K_service et y trouve le nom du client
    et K_c_service, sans jamais contacter le KDC ;
  - ouvre l'authenticator avec K_c_service et vérifie : même client,
    timestamp récent, ticket non expiré, authenticator jamais vu ;
  - répond enc_part = E(K_c_service, "AP_REP", {"ts": ts + 1}) : seul quelqu'un
    qui a pu ouvrir le ticket connaît K_c_service, donc le client sait qu'il
    parle au vrai service (authentification mutuelle) ;
  - donne l'accès au client (ici : un message de log « accès accordé »).

Lancement, depuis la racine du dépôt :
    python -m service.service

Les étapes TODO sont numérotées comme dans service/README.md.
"""

import threading
import time

from common import config
from common.crypto import DecryptError, decrypt, encrypt
from common.net import error, serv

replay_cache = {}
cache_lock = threading.Lock()
K_SERVICE = bytes.fromhex(config.K_SERVICE)


def handle_ap_req(msg):

    if (not isinstance(msg, dict)
            or msg.get("type") != "AP_REQ"
            or "ticket" not in msg
            or "auth" not in msg):
        return error("requête invalide")

    try:
        try:
            ticket = decrypt(K_SERVICE, msg["ticket"], "TICKET")
        except DecryptError:
            return error("ticket invalide")
        k_c_service = bytes.fromhex(ticket["k_c_service"])

        if not time.time() < ticket["exp"]:
            return error("ticket expiré")

        try:
            auth = decrypt(k_c_service, msg["auth"], "AP_AUTH")
        except DecryptError:
            return error("authenticator invalide")


        if auth["client"] != ticket["client"]:
            return error("client de l'authenticator différent de celui du ticket")


        now = time.time()
        if abs(now - auth["ts"]) > config.CLOCK_SKEW:
            return error("timestamp hors de la fenêtre autorisée")


        cle = (auth["client"], auth["ts"])
        with cache_lock:
            for c in [c for c, oubli in replay_cache.items() if oubli <= now]:
                del replay_cache[c]

            if cle in replay_cache:
                return error("authenticator déjà utilisé (rejeu)")

            replay_cache[cle] = auth["ts"] + config.CLOCK_SKEW


        enc_part = encrypt(k_c_service, {"ts": auth["ts"] + 1}, "AP_REP")

    except (KeyError, TypeError, ValueError):
        return error("requête invalide")

    print(f"accès accordé à {ticket['client']}")
    return {"type": "AP_REP", "enc_part": enc_part}

def main() -> None:
    k_service = config.load_keys()[SERVICE_NAME]
    serve(config.HOST, config.SERVICE_PORT, lambda msg: handle_request(msg, k_service), NAME)


if __name__ == "__main__":
    main()
