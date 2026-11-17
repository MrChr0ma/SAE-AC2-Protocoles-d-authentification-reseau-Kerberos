"""Partie 1 : le client (Alice), qui enchaîne les trois échanges du protocole.

  1. AS      : envoie son nom, reçoit enc_part + TGT. Ouvre enc_part avec
               K_client (dérivée de son mot de passe) et récupère K_c_tgs.
               Si le mot de passe est faux, le déchiffrement échoue.
  2. TGS     : envoie TGT + authenticator chiffré avec K_c_tgs + nom du service,
               reçoit enc_part + ticket. Ouvre enc_part avec K_c_tgs et
               récupère K_c_service.
  3. Service : envoie ticket + authenticator chiffré avec K_c_service, reçoit
               E(K_c_service, ts + 1) et vérifie ts + 1 (authentification mutuelle).

Le client ne peut lire ni le TGT ni le ticket : il les transporte tels quels.
Le mot de passe ne quitte jamais la machine du client.

Lancement, depuis la racine du dépôt (les trois serveurs doivent tourner) :
    python -m client.client
    python -m client.client --user alice --password motdepasse --service mail

Les étapes TODO sont numérotées comme dans client/README.md.
"""

import argparse
import getpass
import time  # noqa: F401  (utile pour les authenticators)

from common import config
from common.crypto import DecryptError, decrypt, derive_key, encrypt  # noqa: F401
from common.net import send_request  # noqa: F401


def show(step: str, text: str) -> None:
    """Affiche une étape de la démo, ex. show("AS", "TGT reçu")."""
    print(f"[CLIENT] [{step}] {text}", flush=True)


def short(hex_value: str, n: int = 16) -> str:
    """Raccourcit une longue valeur hex pour l'affichage : '3fa1...9c0e'."""
    return hex_value if len(hex_value) <= 2 * n else f"{hex_value[:n]}...{hex_value[-n:]}"


def run(user: str, password: str, service: str) -> bool:
    """Déroule les trois échanges. Renvoie True si l'accès au service est obtenu."""
    # --- Échange 1 : AS --------------------------------------------------
    # TODO 1 : dériver la clé du client : k_client = derive_key(password, user)
    #          (le sel est le nom du client)

    # TODO 2 : envoyer {"type": "AS_REQ", "client": user} à (config.HOST, config.AS_PORT)
    #          avec send_request ; si la réponse est de type "ERROR", afficher la raison
    #          et return False

    # TODO 3 : ouvrir rep["enc_part"] avec decrypt(k_client, ..., "AS_REP")
    #          DecryptError -> afficher « mot de passe incorrect » et return False
    #          récupérer k_c_tgs = bytes.fromhex(...) et garder rep["tgt"] tel quel
    #          afficher : TGT reçu (raccourci avec short), date d'expiration

    # --- Échange 2 : TGS -------------------------------------------------
    # TODO 4 : fabriquer l'authenticator
    #          auth = encrypt(k_c_tgs, {"client": user, "ts": time.time()}, "TGS_AUTH")

    # TODO 5 : envoyer {"type": "TGS_REQ", "tgt": tgt, "service": service, "auth": auth}
    #          à (config.HOST, config.TGS_PORT) ; gérer "ERROR" comme à l'étape 2

    # TODO 6 : ouvrir rep["enc_part"] avec decrypt(k_c_tgs, ..., "TGS_REP")
    #          récupérer k_c_service et garder rep["ticket"] tel quel
    #          afficher : ticket de service reçu

    # --- Échange 3 : service ---------------------------------------------
    # TODO 7 : fabriquer l'authenticator en GARDANT ts dans une variable
    #          ts = time.time()
    #          auth = encrypt(k_c_service, {"client": user, "ts": ts}, "AP_AUTH")

    # TODO 8 : envoyer {"type": "AP_REQ", "ticket": ticket, "auth": auth}
    #          à (config.HOST, config.SERVICE_PORT) ; gérer "ERROR"

    # TODO 9 : ouvrir rep["enc_part"] avec decrypt(k_c_service, ..., "AP_REP")
    #          vérifier que la valeur "ts" reçue == ts + 1
    #          sinon (ou DecryptError) -> afficher « service non authentifié » et return False

    # TODO 10 : afficher « authentification mutuelle réussie, accès au service » et return True

    show("-", "non implémenté")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Client Kerberos simplifié.")
    parser.add_argument("--user", default=config.DEFAULT_CLIENT)
    parser.add_argument("--password", help="si absent, il est demandé au clavier")
    parser.add_argument("--service", default=config.DEFAULT_SERVICE)
    args = parser.parse_args()

    password = args.password or getpass.getpass(f"Mot de passe de {args.user} : ")
    ok = run(args.user, password, args.service)
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
