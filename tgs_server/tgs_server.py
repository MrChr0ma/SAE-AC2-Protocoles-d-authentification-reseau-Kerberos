"""Partie 3 : TGS (Ticket Granting Server), deuxième échange du protocole.

Rôle : le client présente son TGT, un authenticator et le nom du service
voulu ("mail"). Le TGS :
  - ouvre le TGT avec K_tgs (lui seul, avec l'AS, connaît cette clé) et y
    trouve le nom du client et K_c_tgs ;
  - ouvre l'authenticator avec K_c_tgs : seul le vrai client a pu le
    fabriquer, puisque K_c_tgs n'a été envoyée qu'à lui (chiffrée avec K_client) ;
  - vérifie : même client, timestamp récent, TGT non expiré, authenticator
    jamais vu (replay cache) ;
  - renvoie enc_part = E(K_c_tgs, "TGS_REP", {"k_c_service", "exp"})
    et ticket = E(K_service, "TICKET", {"client", "k_c_service", "exp"}).

Lancement, depuis la racine du dépôt :
    python -m tgs_server.tgs_server

Les étapes TODO sont numérotées comme dans tgs_server/README.md.
"""

import threading
import time  # noqa: F401  (utile pour les étapes 4 à 8)

from common import config
from common.crypto import DecryptError, decrypt, encrypt, new_session_key  # noqa: F401
from common.net import error, serve

NAME = "TGS"

# Replay cache : authenticators déjà acceptés.
# Clé : (client, ts) ; valeur : l'heure à laquelle on pourra l'oublier.
# Le serveur traite chaque connexion dans un thread : toujours manipuler
# le cache en tenant le verrou (with cache_lock: ...).
replay_cache: dict[tuple[str, float], float] = {}
cache_lock = threading.Lock()


def handle_request(msg: dict, keys: dict[str, bytes]) -> dict:
    """Traite un TGS_REQ et renvoie un TGS_REP ou un ERROR.

    msg  : {"type": "TGS_REQ", "tgt": "...", "service": "mail", "auth": "..."}
    keys : clés long terme (keys["krbtgt"] = K_tgs, keys["mail"] = K_service)
    """
    # TODO 1 : vérifier msg["type"] == "TGS_REQ" et la présence de "tgt", "auth", "service"
    #          sinon -> return error("requête invalide")

    # TODO 2 : vérifier que le service demandé existe :
    #          service dans config.SERVICES et dans keys
    #          sinon -> return error("service inconnu")

    # TODO 3 : ouvrir le TGT
    #          tgt = decrypt(keys[config.TGS_PRINCIPAL], msg["tgt"], "TGT")
    #          DecryptError -> return error("TGT invalide")
    #          k_c_tgs = bytes.fromhex(tgt["k_c_tgs"])

    # TODO 4 : vérifier que le TGT n'a pas expiré : time.time() < tgt["exp"]
    #          sinon -> return error("TGT expiré")

    # TODO 5 : ouvrir l'authenticator
    #          auth = decrypt(k_c_tgs, msg["auth"], "TGS_AUTH")
    #          DecryptError -> return error("authenticator invalide")

    # TODO 6 : vérifier que auth["client"] == tgt["client"]
    #          sinon -> return error("client de l'authenticator différent de celui du TGT")

    # TODO 7 : vérifier que abs(time.time() - auth["ts"]) <= config.CLOCK_SKEW
    #          sinon -> return error("timestamp hors de la fenêtre autorisée")

    # TODO 8 : replay cache (sous cache_lock) :
    #          - supprimer les entrées dont l'heure d'oubli est passée ;
    #          - si (client, ts) est déjà présent -> return error("authenticator déjà utilisé (rejeu)")
    #          - sinon l'ajouter avec l'heure d'oubli auth["ts"] + config.CLOCK_SKEW

    # TODO 9 : générer k_c_service = new_session_key()
    #          et exp = min(time.time() + config.TICKET_LIFETIME, tgt["exp"])

    # TODO 10 : construire
    #          enc_part = encrypt(k_c_tgs, {"k_c_service": ..., "exp": exp}, "TGS_REP")
    #          ticket   = encrypt(keys[service], {"client": ..., "k_c_service": ..., "exp": exp}, "TICKET")

    # TODO 11 : renvoyer {"type": "TGS_REP", "enc_part": enc_part, "ticket": ticket}
    #           et afficher une ligne de log pour la démo

    return error("non implémenté")


def main() -> None:
    keys = config.load_keys()
    serve(config.HOST, config.TGS_PORT, lambda msg: handle_request(msg, keys), NAME)


if __name__ == "__main__":
    main()
