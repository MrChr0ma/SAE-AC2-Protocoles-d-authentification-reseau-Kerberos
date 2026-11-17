"""Partie 2 : AS (Authentication Server), premier échange du protocole.

Rôle : le client donne seulement son nom ("alice"). L'AS lui renvoie :
  - enc_part = E(K_client, "AS_REP", {"k_c_tgs", "exp"})
        lisible uniquement par quelqu'un qui connaît le mot de passe d'alice :
        c'est ce qui prouve son identité, sans que le mot de passe circule ;
  - tgt      = E(K_tgs, "TGT", {"client", "k_c_tgs", "exp"})
        opaque pour alice (elle ne connaît pas K_tgs), elle le transporte
        jusqu'au TGS comme un badge.

Dans un vrai Kerberos, l'AS et le TGS sont le même programme (le KDC).
Ici ce sont deux programmes séparés qui lisent tous deux K_tgs dans keys.json.

Lancement, depuis la racine du dépôt :
    python -m as_server.as_server

Les étapes TODO sont numérotées comme dans as_server/README.md.
"""

import time  # noqa: F401  (utile pour l'étape 4)

from common import config
from common.crypto import encrypt, new_session_key  # noqa: F401
from common.net import error, serve

NAME = "AS"


def handle_request(msg: dict, keys: dict[str, bytes]) -> dict:
    """Traite un AS_REQ et renvoie un AS_REP ou un ERROR.

    msg  : le message reçu, ex. {"type": "AS_REQ", "client": "alice"}
    keys : les clés long terme chargées depuis keys.json
           (keys["alice"] = K_client, keys["krbtgt"] = K_tgs)
    """
    # TODO 1 : vérifier que msg["type"] == "AS_REQ" et que "client" est présent
    #          sinon -> return error("requête invalide")

    # TODO 2 : récupérer client = msg["client"] et vérifier qu'il existe :
    #          client dans keys, différent de config.TGS_PRINCIPAL,
    #          et pas dans config.SERVICES
    #          sinon -> return error("client inconnu")
    #          k_client = keys[client] ; k_tgs = keys[config.TGS_PRINCIPAL]

    # TODO 3 : générer la clé de session client <-> TGS
    #          k_c_tgs = new_session_key()

    # TODO 4 : calculer l'expiration avec l'heure du serveur
    #          exp = time.time() + config.TICKET_LIFETIME

    # TODO 5 : construire la partie pour le client
    #          enc_part = encrypt(k_client, {"k_c_tgs": k_c_tgs.hex(), "exp": exp}, "AS_REP")

    # TODO 6 : construire le TGT
    #          tgt = encrypt(k_tgs, {"client": client, "k_c_tgs": k_c_tgs.hex(), "exp": exp}, "TGT")

    # TODO 7 : renvoyer {"type": "AS_REP", "enc_part": enc_part, "tgt": tgt}
    #          et afficher une ligne de log pour la démo (sans afficher les clés en entier)

    return error("non implémenté")


def main() -> None:
    keys = config.load_keys()
    serve(config.HOST, config.AS_PORT, lambda msg: handle_request(msg, keys), NAME)


if __name__ == "__main__":
    main()
