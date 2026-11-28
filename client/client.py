import argparse
import getpass
import time

from common import config
from common.crypto import DecryptError, decrypt, derive_key, encrypt
from common.net import ProtocolError, send_request


def show(step: str, text: str) -> None:
    """Affiche une étape du client pendant la démonstration."""
    print(f"[CLIENT] [{step}] {text}", flush=True)


def short(value: str, n: int = 16) -> str:
    """Raccourcit une longue valeur hexadécimale pour l'affichage."""
    if len(value) <= 2 * n:
        return value
    return f"{value[:n]}...{value[-n:]}"


def format_exp(exp: float) -> str:
    """Convertit un timestamp Unix en heure locale lisible."""
    return time.strftime("%H:%M:%S", time.localtime(exp))


def extraire_cle(part: dict, nom: str) -> bytes:
    """Récupère une clé de session hexadécimale et vérifie qu'elle fait 16 octets."""
    valeur = part.get(nom)
    if not isinstance(valeur, str):
        raise ValueError(f"champ {nom} absent ou invalide")

    try:
        cle = bytes.fromhex(valeur)
    except ValueError as exc:
        raise ValueError(f"champ {nom} invalide") from exc

    if len(cle) != 16:
        raise ValueError(f"taille invalide pour {nom}")

    return cle


def lire_expiration(part: dict) -> str:
    """Vérifie que la date d'expiration est un nombre et la renvoie formatée."""
    exp = part.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise ValueError("date d'expiration absente ou invalide")
    return format_exp(exp)


def run(user: str, password: str, service: str) -> bool:
    """Effectue les trois échanges ; renvoie True si le service est authentifié."""
    k_client = derive_key(password, user)

    show("AS", f"envoi de AS_REQ pour '{user}' vers {config.HOST}:{config.AS_PORT}")

    try:
        as_rep = send_request(
            config.HOST,
            config.AS_PORT,
            {"type": "AS_REQ", "client": user},
        )
    except OSError:
        show("AS", "impossible de joindre l'AS")
        return False
    except ProtocolError:
        show("AS", "réponse de l'AS invalide ou incomplète")
        return False

    if as_rep.get("type") == "ERROR":
        show("AS", f"erreur du serveur : {as_rep.get('reason', 'erreur inconnue')}")
        return False

    if (
        as_rep.get("type") != "AS_REP"
        or not isinstance(as_rep.get("enc_part"), str)
        or not isinstance(as_rep.get("tgt"), str)
    ):
        show("AS", "réponse de l'AS invalide")
        return False

    try:
        as_part = decrypt(k_client, as_rep["enc_part"], "AS_REP")
    except DecryptError:
        show("AS", "mot de passe incorrect")
        return False

    try:
        k_c_tgs = extraire_cle(as_part, "k_c_tgs")
        expiration_tgt = lire_expiration(as_part)
        tgt = as_rep["tgt"]
    except (TypeError, ValueError, OverflowError, OSError):
        show("AS", "réponse de l'AS invalide")
        return False

    show("AS", f"TGT reçu : {short(tgt)}, expire à {expiration_tgt}")

    auth_tgs = encrypt(
        k_c_tgs,
        {"client": user, "ts": time.time()},
        "TGS_AUTH",
    )
    show("TGS", f"envoi de TGS_REQ pour le service '{service}'")

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

    ts = time.time()
    auth_service = encrypt(
        k_c_service,
        {"client": user, "ts": ts},
        "AP_AUTH",
    )
    show("SERVICE", f"envoi de AP_REQ au service '{service}'")

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

    try:
        ap_part = decrypt(k_c_service, ap_rep["enc_part"], "AP_REP")
    except DecryptError:
        show("SERVICE", "service non authentifié : authentification mutuelle échouée")
        return False

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

    password = args.password or getpass.getpass(f"Mot de passe de {args.user} : ")

    ok = run(args.user, password, args.service)
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
