import time
from common.crypto import decrypt, derive_key, new_session_key
from as_server.as_server import handle_request

KEYS = {"alice": derive_key("motdepasse", "alice"),
        "krbtgt": new_session_key(), "mail": new_session_key()}

def test_as_rep():
    rep = handle_request({"type": "AS_REQ", "client": "alice"}, KEYS)
    assert rep["type"] == "AS_REP"
    part = decrypt(KEYS["alice"], rep["enc_part"], "AS_REP")
    tgt = decrypt(KEYS["krbtgt"], rep["tgt"], "TGT")
    assert tgt["client"] == "alice"
    assert tgt["k_c_tgs"] == part["k_c_tgs"]
    assert tgt["exp"] == part["exp"] > time.time()

def test_client_inconnu():
    assert handle_request({"type": "AS_REQ", "client": "bob"}, KEYS)["type"] == "ERROR"