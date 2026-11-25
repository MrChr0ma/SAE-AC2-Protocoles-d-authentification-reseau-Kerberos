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

Replay cache : replay_cache garde les authenticators déjà acceptés, avec pour
clé (client, ts) et pour valeur l'heure à laquelle on pourra l'oublier. Chaque
connexion est traitée dans son propre thread : le cache se manipule toujours
en tenant cache_lock.

Lancement, depuis la racine du dépôt :
    python -m tgs_server.tgs_server

Les étapes TODO restantes sont numérotées comme dans tgs_server/README.md.
"""

import threading
import time

from common import config
from common.crypto import DecryptError, decrypt, encrypt, new_session_key
from common.net import error, serve

NAME = "TGS"

replay_cache: dict[tuple[str, float], float] = {}
cache_lock = threading.Lock()


def est_nombre(valeur) -> bool:
    """Indique si valeur est un nombre utilisable comme timestamp Unix.

    Un booléen est refusé, même si Python considère True et False comme des
    entiers : un champ "exp" ou "ts" à True ne doit pas passer pour une date.
    """
    return isinstance(valeur, (int, float)) and not isinstance(valeur, bool)


def lire_cle(part: dict, nom: str) -> bytes | None:
    """Récupère une clé de session transportée en hexadécimal dans un dictionnaire.

    Renvoie la clé en octets si le champ existe, est de l'hexadécimal valide et
    fait 16 octets (AES-128), sinon None. Un champ absent ou abîmé veut dire que
    le chiffré a été fabriqué par quelqu'un d'autre que l'AS.
    """
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


def handle_request(msg: dict, keys: dict[str, bytes]) -> dict:
    """Traite un TGS_REQ et renvoie un TGS_REP ou un ERROR.

    msg  : {"type": "TGS_REQ", "tgt": "...", "service": "mail", "auth": "..."}
    keys : clés long terme (keys["krbtgt"] = K_tgs, keys["mail"] = K_service)

    Les contrôles sont faits dans l'ordre du README et la fonction s'arrête au
    premier qui échoue. Toutes les vérifications de temps utilisent l'heure du
    serveur, jamais une heure envoyée en clair par le client.
    """
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
    """Charge les clés long terme et lance le serveur TGS sur son port."""
    keys = config.load_keys()
    serve(config.HOST, config.TGS_PORT, lambda msg: handle_request(msg, keys), NAME)


if __name__ == "__main__":
    main()
