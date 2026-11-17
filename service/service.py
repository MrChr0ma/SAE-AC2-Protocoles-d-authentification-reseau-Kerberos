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
import time  # noqa: F401  (utile pour les étapes 3 à 7)

from common import config
from common.crypto import DecryptError, decrypt, encrypt  # noqa: F401
from common.net import error, serve

NAME = "SERVICE"
SERVICE_NAME = config.DEFAULT_SERVICE  # "mail" : son entrée dans keys.json contient K_service

# Replay cache : authenticators déjà acceptés.
# Clé : (client, ts) ; valeur : l'heure à laquelle on pourra l'oublier.
# Toujours le manipuler en tenant le verrou (with cache_lock: ...).
replay_cache: dict[tuple[str, float], float] = {}
cache_lock = threading.Lock()


def handle_request(msg: dict, k_service: bytes) -> dict:
    """Traite un AP_REQ et renvoie un AP_REP ou un ERROR.

    msg       : {"type": "AP_REQ", "ticket": "...", "auth": "..."}
    k_service : la clé long terme du service (keys["mail"])
    """
    # TODO 1 : vérifier msg["type"] == "AP_REQ" et la présence de "ticket" et "auth"
    #          sinon -> return error("requête invalide")

    # TODO 2 : ouvrir le ticket
    #          ticket = decrypt(k_service, msg["ticket"], "TICKET")
    #          DecryptError -> return error("ticket invalide")
    #          k_c_service = bytes.fromhex(ticket["k_c_service"])

    # TODO 3 : vérifier que le ticket n'a pas expiré : time.time() < ticket["exp"]
    #          sinon -> return error("ticket expiré")

    # TODO 4 : ouvrir l'authenticator
    #          auth = decrypt(k_c_service, msg["auth"], "AP_AUTH")
    #          DecryptError -> return error("authenticator invalide")

    # TODO 5 : vérifier que auth["client"] == ticket["client"]
    #          sinon -> return error("client de l'authenticator différent de celui du ticket")

    # TODO 6 : vérifier que abs(time.time() - auth["ts"]) <= config.CLOCK_SKEW
    #          sinon -> return error("timestamp hors de la fenêtre autorisée")

    # TODO 7 : replay cache (sous cache_lock) :
    #          - supprimer les entrées dont l'heure d'oubli est passée ;
    #          - si (client, ts) est déjà présent -> return error("authenticator déjà utilisé (rejeu)")
    #          - sinon l'ajouter avec l'heure d'oubli auth["ts"] + config.CLOCK_SKEW

    # TODO 8 : construire la preuve pour le client
    #          enc_part = encrypt(k_c_service, {"ts": auth["ts"] + 1}, "AP_REP")

    # TODO 9 : afficher « accès accordé à <client> » dans le log
    #          et renvoyer {"type": "AP_REP", "enc_part": enc_part}

    return error("non implémenté")


def main() -> None:
    k_service = config.load_keys()[SERVICE_NAME]
    serve(config.HOST, config.SERVICE_PORT, lambda msg: handle_request(msg, k_service), NAME)


if __name__ == "__main__":
    main()
