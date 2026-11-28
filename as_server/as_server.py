import time
from common import config
from common.crypto import encrypt, new_session_key
from common.net import error, serve

def handle_request(msg: dict, keys: dict) -> dict:
    """Vérifie un AS_REQ et renvoie le TGT et la clé de session, ou un ERROR."""
    if not isinstance(msg, dict) or msg.get("type") != "AS_REQ" or "client" not in msg:
        return error("requête invalide")
    client = msg["client"]
    if not isinstance(client, str) or not client:
        return error("requête invalide")
    if (client not in keys or client == config.TGS_PRINCIPAL or client in config.SERVICES):
        return error("client inconnu")
    k_client = keys[client]
    k_tgs = keys[config.TGS_PRINCIPAL]
    k_c_tgs = new_session_key()
    exp = time.time() + config.TICKET_LIFETIME
    k_c_tgs_hex = k_c_tgs.hex()
    enc_part = encrypt(k_client,{"k_c_tgs": k_c_tgs_hex, "exp": exp},"AS_REP",)
    tgt = encrypt(k_tgs,{"client": client, "k_c_tgs": k_c_tgs_hex, "exp": exp},"TGT",)
    print(f"[AS] AS_REP envoyé pour '{client}' (exp={exp:.0f})")
    return {"type": "AS_REP","enc_part": enc_part,"tgt": tgt,}

def main() -> None:
    """Charge les clés long terme et lance l'AS sur son port."""
    keys = config.load_keys()
    serve(config.HOST, config.AS_PORT, lambda msg: handle_request(msg, keys), "AS")

if __name__ == "__main__":
    main()