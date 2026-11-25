import time

from common import config
from common.crypto import encrypt, new_session_key
from common.net import error


def handle_request(msg: dict, keys: dict) -> dict:
    if not isinstance(msg, dict) or msg.get("type") != "AS_REQ" or "client" not in msg:
        return error("La requete est invalide")

    client = msg["client"]
    if not isinstance(client, str) or not client:
        return error("la requete est invalide")
    if (client not in keys or client == config.TGS_PRINCIPAL or client in config.SERVICES):
        return error("Le client est inconnu")
    k_client = keys[client]
    k_tgs = keys[config.TGS_PRINCIPAL]
    k_c_tgs = new_session_key()
    exp = time.time() + config.TICKET_LIFETIME
    k_c_tgs_hex = k_c_tgs.hex()
    enc_part = encrypt(k_client,{"k_c_tgs": k_c_tgs_hex, "exp": exp},"AS_REP",)
    tgt = encrypt(k_tgs,{"client": client, "k_c_tgs": k_c_tgs_hex, "exp": exp},"TGT",)
    print(f"[AS] AS_REP envoyé pour '{client}' (exp={exp:.0f})")
    return {"type": "AS_REP","enc_part": enc_part,"tgt": tgt,}