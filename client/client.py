"""Partie 1 : le client (Alice) et les trois échanges Kerberos.

Le rôle du client est de demander les tickets nécessaires, puis de les présenter
aux bons serveurs. Il ne fabrique pas lui-même les tickets : ils sont créés par
l'AS et le TGS, puis protégés avec les clés que seuls ces serveurs connaissent.

Le déroulement est toujours le même :
    1. demander un TGT à l'AS ;
    2. présenter ce TGT au TGS pour obtenir un ticket de service ;
    3. présenter le ticket de service au service et vérifier sa réponse.

À retenir : le TGT et le ticket de service restent chiffrés pendant tout le
parcours. Le client les transporte tels quels, sans chercher à les lire. Le
mot de passe n'est utilisé que localement pour dériver K_client : il n'est
jamais ajouté aux messages envoyés sur le réseau.

Lancement depuis la racine du dépôt :
    python -m client.client
    python -m client.client --user alice --password motdepasse --service mail
"""

import argparse
import getpass
import time

from common import config
from common.crypto import DecryptError, decrypt, derive_key, encrypt
from common.net import ProtocolError, send_request


def show(step: str, text: str) -> None:
    """Affiche une étape du client pendant la démonstration.

    Le préfixe permet de voir immédiatement quel acteur est concerné dans le
    terminal. flush=True force l'affichage tout de suite, ce qui est pratique
    quand plusieurs programmes tournent dans des terminaux différents.
    """
    print(f"[CLIENT] [{step}] {text}", flush=True)


def short(value: str, n: int = 16) -> str:
    """Raccourcit une longue chaîne hexadécimale pour l'affichage.

    Un ticket chiffré peut être assez long. Pour la démonstration, je veux
    montrer qu'il a bien été reçu sans remplir tout le terminal ni afficher
    une valeur complète qui n'apporte pas grand-chose à la lecture.
    Cette fonction ne modifie pas le ticket : elle ne sert qu'à l'affichage.
    """
    if len(value) <= 2 * n:
        return value
    return f"{value[:n]}...{value[-n:]}"


def format_exp(exp: float) -> str:
    """Convertit une date d'expiration Unix en heure locale lisible.

    Dans le protocole, exp est un timestamp Unix (un nombre de secondes depuis
    le 1er janvier 1970). Je le convertis uniquement pour l'afficher plus
    facilement. La valeur utilisée par le protocole reste celle reçue du serveur.
    """
    return time.strftime("%H:%M:%S", time.localtime(exp))


def extraire_cle(part: dict, nom: str) -> bytes:
    """Récupère et vérifie une clé de session encodée en hexadécimal.

    Les clés sont transportées dans les dictionnaires JSON sous forme de texte
    hexadécimal. Pour les utiliser avec encrypt() et decrypt(), il faut revenir
    à des octets avec bytes.fromhex().

    Je vérifie aussi le type et la taille : dans ce projet, les clés utilisées
    par AES sont des clés AES-128, donc elles doivent faire exactement 16 octets.
    Cela évite de continuer avec une réponse serveur incomplète ou incorrecte.
    """
    valeur = part.get(nom)
    if not isinstance(valeur, str):
        raise ValueError(f"champ {nom} absent ou invalide")

    try:
        cle = bytes.fromhex(valeur)
    except ValueError as exc:
        raise ValueError(f"champ {nom} invalide") from exc

    # AES-128 utilise une clé de 128 bits : 128 / 8 = 16 octets.
    if len(cle) != 16:
        raise ValueError(f"taille invalide pour {nom}")

    return cle


def lire_expiration(part: dict) -> str:
    """Vérifie le champ d'expiration et le formate pour l'affichage.

    Je m'assure que le champ existe et contient un nombre. Le booléen est
    explicitement refusé, même si Python considère True et False comme des
    sous-types de int. La vérification réelle de l'expiration du ticket est
    faite côté serveur lorsqu'il reçoit le ticket ; ici, je l'affiche seulement.
    """
    exp = part.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise ValueError("date d'expiration absente ou invalide")
    return format_exp(exp)


def run(user: str, password: str, service: str) -> bool:
    """Effectue les trois échanges. Renvoie True si le service est authentifié.

    La fonction renvoie False dès qu'un échange échoue. Cela évite d'envoyer
    une requête au serveur suivant avec un ticket ou une clé qui n'a pas été
    obtenu correctement à l'étape précédente.
    """

    # =====================================================================
    # ÉCHANGE 1 — AS : obtenir le TGT (Ticket Granting Ticket)
    # =====================================================================
    # Le client et l'AS doivent pouvoir retrouver la même K_client à partir
    # du mot de passe. La fonction commune utilise PBKDF2-HMAC-SHA256 ; le nom
    # du client sert de sel, conformément au choix fait dans notre projet.
    # Le mot de passe reste dans ce programme : seul le nom d'utilisateur sera
    # envoyé à l'AS dans le message AS_REQ.
    k_client = derive_key(password, user)

    show("AS", f"envoi de AS_REQ pour '{user}' vers {config.HOST}:{config.AS_PORT}")

    # AS_REQ est volontairement simple : le client annonce son identité, mais
    # n'envoie ni son mot de passe ni K_client. L'AS répond avec deux éléments :
    # - enc_part, chiffré avec K_client et donc lisible par le client qui connaît
    #   le bon mot de passe ;
    # - tgt, chiffré avec K_tgs et que le client ne peut pas ouvrir.
    try:
        as_rep = send_request(
            config.HOST,
            config.AS_PORT,
            {"type": "AS_REQ", "client": user},
        )
    except OSError:
        # OSError couvre notamment le refus de connexion et certains problèmes
        # réseau (serveur arrêté, délai dépassé, connexion interrompue).
        show("AS", "impossible de joindre l'AS")
        return False
    except ProtocolError:
        # Ici, la connexion a pu avoir lieu, mais le message reçu n'a pas pu
        # être interprété correctement par le protocole JSON/TCP du projet.
        show("AS", "réponse de l'AS invalide ou incomplète")
        return False

    # Les serveurs peuvent renvoyer un message ERROR plutôt qu'une réponse
    # normale. Dans ce cas, on affiche la raison donnée et on s'arrête.
    if as_rep.get("type") == "ERROR":
        show("AS", f"erreur du serveur : {as_rep.get('reason', 'erreur inconnue')}")
        return False

    # Je vérifie la structure minimale de la réponse avant de lire ses champs.
    # Cela évite un KeyError si le serveur ne respecte pas le format attendu.
    if (
        as_rep.get("type") != "AS_REP"
        or not isinstance(as_rep.get("enc_part"), str)
        or not isinstance(as_rep.get("tgt"), str)
    ):
        show("AS", "réponse de l'AS invalide")
        return False

    # enc_part contient notamment K_c_tgs et la date d'expiration du TGT.
    # Elle est chiffrée avec K_client : si le mot de passe saisi est mauvais,
    # la clé dérivée ne permettra normalement pas de vérifier le tag AES-GCM.
    # DecryptError est donc traité ici comme un mot de passe incorrect.
    try:
        as_part = decrypt(k_client, as_rep["enc_part"], "AS_REP")
    except DecryptError:
        show("AS", "mot de passe incorrect")
        return False

    # Une fois enc_part déchiffrée, je récupère la clé de session qui servira
    # pour parler au TGS. Le TGT est conservé tel quel : il est destiné au TGS,
    # qui possède K_tgs, et le client n'a pas besoin de connaître son contenu.
    try:
        k_c_tgs = extraire_cle(as_part, "k_c_tgs")
        expiration_tgt = lire_expiration(as_part)
        tgt = as_rep["tgt"]
    except (TypeError, ValueError, OverflowError, OSError):
        show("AS", "réponse de l'AS invalide")
        return False

    show("AS", f"TGT reçu : {short(tgt)}, expire à {expiration_tgt}")

    # =====================================================================
    # ÉCHANGE 2 — TGS : obtenir un ticket pour le service demandé
    # =====================================================================
    # Le TGT seul ne suffit pas : le client doit aussi prouver qu'il connaît
    # K_c_tgs. Pour cela, il crée un authenticator contenant son nom et l'heure
    # actuelle. Cet authenticator est chiffré avec K_c_tgs.
    #
    # Le troisième argument "TGS_AUTH" est l'AAD (Additional Authenticated
    # Data). Il n'est pas chiffré comme le contenu, mais il est authentifié par
    # AES-GCM. Il sert à identifier le rôle du message et évite de réutiliser
    # par erreur un chiffré prévu pour un autre usage.
    auth_tgs = encrypt(
        k_c_tgs,
        {"client": user, "ts": time.time()},
        "TGS_AUTH",
    )
    show("TGS", f"envoi de TGS_REQ pour le service '{service}'")

    # Le client envoie au TGS le TGT opaque, le nom du service demandé et
    # l'authenticator. Le TGS pourra ouvrir le TGT avec K_tgs, récupérer
    # K_c_tgs, puis vérifier l'authenticator et son timestamp.
    try:
        tgs_rep = send_request(
            config.HOST,
            config.TGS_PORT,
            {
                "type": "TGS_REQ",
                "tgt": tgt,
                "service": service,
                "auth": auth_tgs,
            },
        )
    except OSError:
        show("TGS", "impossible de joindre le TGS")
        return False
    except ProtocolError:
        show("TGS", "réponse du TGS invalide ou incomplète")
        return False

    if tgs_rep.get("type") == "ERROR":
        show("TGS", f"erreur du serveur : {tgs_rep.get('reason', 'erreur inconnue')}")
        return False

    if (
        tgs_rep.get("type") != "TGS_REP"
        or not isinstance(tgs_rep.get("enc_part"), str)
        or not isinstance(tgs_rep.get("ticket"), str)
    ):
        show("TGS", "réponse du TGS invalide")
        return False

    # Le TGS renvoie lui aussi deux éléments : une partie lisible par le client
    # (chiffrée avec K_c_tgs) et un ticket de service que seul le service pourra
    # ouvrir avec sa propre clé à long terme K_service.
    # Je déchiffre enc_part pour récupérer K_c_service, mais je ne touche pas
    # au ticket : il sera présenté directement au service à l'échange suivant.
    try:
        tgs_part = decrypt(k_c_tgs, tgs_rep["enc_part"], "TGS_REP")
    except DecryptError:
        show("TGS", "réponse du TGS invalide")
        return False

    try:
        k_c_service = extraire_cle(tgs_part, "k_c_service")
        expiration_ticket = lire_expiration(tgs_part)
        ticket = tgs_rep["ticket"]
    except (TypeError, ValueError, OverflowError, OSError):
        show("TGS", "réponse du TGS invalide")
        return False

    show("TGS", f"ticket de service reçu : {short(ticket)}, expire à {expiration_ticket}")

    # =====================================================================
    # ÉCHANGE 3 — SERVICE : présenter le ticket et vérifier son identité
    # =====================================================================
    # Cette fois, l'authenticator est chiffré avec K_c_service. Je stocke le
    # timestamp dans une variable au lieu d'appeler time.time() directement
    # dans le dictionnaire : j'aurai besoin de cette valeur exacte pour vérifier
    # la réponse du service juste après.
    ts = time.time()
    auth_service = encrypt(
        k_c_service,
        {"client": user, "ts": ts},
        "AP_AUTH",
    )
    show("SERVICE", f"envoi de AP_REQ au service '{service}'")

    # Le ticket contient la clé de session et l'identité du client, mais il est
    # chiffré avec K_service. Le service peut donc le lire, contrairement au
    # client. L'authenticator prouve que le client connaît bien K_c_service.
    try:
        ap_rep = send_request(
            config.HOST,
            config.SERVICE_PORT,
            {"type": "AP_REQ", "ticket": ticket, "auth": auth_service},
        )
    except OSError:
        show("SERVICE", "impossible de joindre le service")
        return False
    except ProtocolError:
        show("SERVICE", "réponse du service invalide ou incomplète")
        return False

    if ap_rep.get("type") == "ERROR":
        show("SERVICE", f"erreur du serveur : {ap_rep.get('reason', 'erreur inconnue')}")
        return False

    if ap_rep.get("type") != "AP_REP" or not isinstance(ap_rep.get("enc_part"), str):
        show("SERVICE", "service non authentifié : authentification mutuelle échouée")
        return False

    # Le service répond avec AP_REP, chiffré avec K_c_service. Un service qui
    # ne possède pas la bonne clé ne peut normalement pas produire une réponse
    # AES-GCM valide que le client pourra déchiffrer.
    try:
        ap_part = decrypt(k_c_service, ap_rep["enc_part"], "AP_REP")
    except DecryptError:
        show("SERVICE", "service non authentifié : authentification mutuelle échouée")
        return False

    # On vérifie maintenant la valeur attendue : le service doit renvoyer ts + 1.
    # Cette réponse chiffrée constitue la preuve que le service a pu ouvrir le
    # ticket et retrouver K_c_service. C'est la dernière étape de l'authentification
    # mutuelle : le client a prouvé son identité au service, puis vérifie celle
    # du service grâce à cette réponse.
    if ap_part.get("ts") != ts + 1:
        show("SERVICE", "service non authentifié : authentification mutuelle échouée")
        return False

    show("SERVICE", f"authentification mutuelle réussie, accès au service '{service}'")
    return True


def main() -> None:
    """Lit les options de lancement et démarre l'authentification."""
    parser = argparse.ArgumentParser(description="Client Kerberos simplifié.")
    parser.add_argument("--user", default=config.DEFAULT_CLIENT)
    parser.add_argument("--password", help="si absent, il est demandé au clavier")
    parser.add_argument("--service", default=config.DEFAULT_SERVICE)
    args = parser.parse_args()

    # Si --password n'est pas fourni, getpass demande le mot de passe sans
    # l'afficher pendant la saisie. C'est préférable pour une démonstration.
    # L'option --password reste pratique pour les tests, mais elle peut laisser
    # le mot de passe visible dans l'historique du terminal ou la liste des processus.
    password = args.password or getpass.getpass(f"Mot de passe de {args.user} : ")

    # run() renvoie True seulement si les trois échanges ont réussi et si la
    # réponse finale du service a été vérifiée. Le code de sortie permet aussi
    # à un script ou à un test de savoir si l'authentification a réussi.
    ok = run(args.user, password, args.service)
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
