import time

import pytest

from common import config
from common.crypto import decrypt, encrypt, new_session_key
from tgs_server import tgs_server
from tgs_server.tgs_server import handle_request

KEYS = {config.TGS_PRINCIPAL: new_session_key("aes128"), "mail": new_session_key("aes128")}


@pytest.fixture(autouse=True)
def cache_vide():
    tgs_server.replay_cache.clear()
    yield
    tgs_server.replay_cache.clear()


def fabriquer_requete(exp_decalage=600, ts_decalage=0, client_auth="alice", service="mail",
                      cle_tgt=None, cle_auth=None):
    """Joue le rôle de l'AS et du client : renvoie un TGS_REQ et la clé K_c_tgs utilisée."""
    k_c_tgs = new_session_key("aes128")
    tgt = encrypt(cle_tgt or KEYS[config.TGS_PRINCIPAL],
                  {"client": "alice", "k_c_tgs": k_c_tgs.hex(), "exp": time.time() + exp_decalage},
                  "TGT")
    auth = encrypt(cle_auth or k_c_tgs, {"client": client_auth, "ts": time.time() + ts_decalage},
                   "TGS_AUTH")
    return {"type": "TGS_REQ", "tgt": tgt, "service": service, "auth": auth}, k_c_tgs


def raison(rep):
    """Renvoie la raison d'un message ERROR, ou None si la réponse n'en est pas un."""
    return rep.get("reason") if rep.get("type") == "ERROR" else None


def test_ticket_delivre():
    req, k_c_tgs = fabriquer_requete()
    rep = handle_request(req, KEYS)
    assert rep["type"] == "TGS_REP"
    part = decrypt(k_c_tgs, rep["enc_part"], "TGS_REP")
    ticket = decrypt(KEYS["mail"], rep["ticket"], "TICKET")
    assert ticket["client"] == "alice"
    assert ticket["k_c_service"] == part["k_c_service"]
    assert len(bytes.fromhex(ticket["k_c_service"])) == 16
    assert ticket["exp"] == part["exp"] > time.time()


def test_ticket_ne_depasse_pas_le_tgt():
    req, k_c_tgs = fabriquer_requete(exp_decalage=60)
    rep = handle_request(req, KEYS)
    part = decrypt(k_c_tgs, rep["enc_part"], "TGS_REP")
    assert part["exp"] <= time.time() + 60


def test_rejeu_refuse():
    req, _ = fabriquer_requete()
    assert handle_request(req, KEYS)["type"] == "TGS_REP"
    assert raison(handle_request(req, KEYS)) == "authenticator déjà utilisé (rejeu)"


def test_deux_requetes_differentes_acceptees():
    req1, _ = fabriquer_requete()
    req2, _ = fabriquer_requete()
    assert handle_request(req1, KEYS)["type"] == "TGS_REP"
    assert handle_request(req2, KEYS)["type"] == "TGS_REP"


@pytest.mark.parametrize("msg", [
    {"type": "AS_REQ"},
    {"type": "TGS_REQ", "service": "mail", "auth": "00"},
    {"type": "TGS_REQ", "tgt": 12, "service": "mail", "auth": "00"},
])
def test_requete_invalide(msg):
    assert raison(handle_request(msg, KEYS)) == "requête invalide"


@pytest.mark.parametrize("service", ["imprimante", config.TGS_PRINCIPAL, "alice"])
def test_service_inconnu(service):
    req, _ = fabriquer_requete(service=service)
    assert raison(handle_request(req, KEYS)) == "service inconnu"


def test_tgt_chiffre_avec_une_autre_cle():
    req, _ = fabriquer_requete(cle_tgt=new_session_key("aes128"))
    assert raison(handle_request(req, KEYS)) == "TGT invalide"


def test_tgt_modifie():
    req, _ = fabriquer_requete()
    raw = bytearray(bytes.fromhex(req["tgt"]))
    raw[20] ^= 0x01
    req["tgt"] = raw.hex()
    assert raison(handle_request(req, KEYS)) == "TGT invalide"


def test_tgt_expire():
    req, _ = fabriquer_requete(exp_decalage=-1)
    assert raison(handle_request(req, KEYS)) == "TGT expiré"


def test_authenticator_avec_une_autre_cle():
    req, _ = fabriquer_requete(cle_auth=new_session_key("aes128"))
    assert raison(handle_request(req, KEYS)) == "authenticator invalide"


def test_authenticator_d_un_autre_client():
    req, _ = fabriquer_requete(client_auth="mallory")
    assert raison(handle_request(req, KEYS)) == "client de l'authenticator différent de celui du TGT"


@pytest.mark.parametrize("decalage", [-config.CLOCK_SKEW - 5, config.CLOCK_SKEW + 5])
def test_timestamp_hors_fenetre(decalage):
    req, _ = fabriquer_requete(ts_decalage=decalage)
    assert raison(handle_request(req, KEYS)) == "timestamp hors de la fenêtre autorisée"


@pytest.mark.parametrize("ts", [float("nan"), float("inf"), 10**400, True])
def test_timestamp_non_fini_refuse(ts):
    k_c_tgs = new_session_key("aes128")
    tgt = encrypt(KEYS[config.TGS_PRINCIPAL],
                  {"client": "alice", "k_c_tgs": k_c_tgs.hex(), "exp": time.time() + 600}, "TGT")
    auth = encrypt(k_c_tgs, {"client": "alice", "ts": ts}, "TGS_AUTH")
    req = {"type": "TGS_REQ", "tgt": tgt, "service": "mail", "auth": auth}
    assert raison(handle_request(req, KEYS)) == "authenticator invalide"


def test_entree_du_cache_gardee_au_dela_de_la_fenetre():
    ts = time.time()
    assert tgs_server.deja_vu("alice", ts, ts) is False
    assert tgs_server.deja_vu("bob", time.time(), ts + config.CLOCK_SKEW + 1) is False
    assert tgs_server.deja_vu("alice", ts, ts + config.CLOCK_SKEW) is True
