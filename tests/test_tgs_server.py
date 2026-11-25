"""Tests des vérifications du TGS (étapes 1 à 7 de tgs_server/README.md)."""

import time

import pytest

from common import config
from common.crypto import encrypt, new_session_key
from tgs_server.tgs_server import handle_request

KEYS = {config.TGS_PRINCIPAL: new_session_key("aes128"), "mail": new_session_key("aes128")}

REFUS = {
    "requête invalide",
    "service inconnu",
    "TGT invalide",
    "TGT expiré",
    "authenticator invalide",
    "client de l'authenticator différent de celui du TGT",
    "timestamp hors de la fenêtre autorisée",
}


def fabriquer_requete(exp_decalage=600, ts_decalage=0, client_auth="alice", service="mail",
                      cle_tgt=None, cle_auth=None):
    """Joue le rôle de l'AS et du client : fabrique un TGS_REQ avec les paramètres voulus."""
    k_c_tgs = new_session_key("aes128")
    tgt = encrypt(cle_tgt or KEYS[config.TGS_PRINCIPAL],
                  {"client": "alice", "k_c_tgs": k_c_tgs.hex(), "exp": time.time() + exp_decalage},
                  "TGT")
    auth = encrypt(cle_auth or k_c_tgs, {"client": client_auth, "ts": time.time() + ts_decalage},
                   "TGS_AUTH")
    return {"type": "TGS_REQ", "tgt": tgt, "service": service, "auth": auth}


def raison(rep):
    """Renvoie la raison d'un message ERROR, ou None si la réponse n'en est pas un."""
    return rep.get("reason") if rep.get("type") == "ERROR" else None


def test_requete_valide_passe_les_verifications():
    assert raison(handle_request(fabriquer_requete(), KEYS)) not in REFUS


@pytest.mark.parametrize("msg", [
    {"type": "AS_REQ"},
    {"type": "TGS_REQ", "service": "mail", "auth": "00"},
    {"type": "TGS_REQ", "tgt": 12, "service": "mail", "auth": "00"},
])
def test_requete_invalide(msg):
    assert raison(handle_request(msg, KEYS)) == "requête invalide"


@pytest.mark.parametrize("service", ["imprimante", config.TGS_PRINCIPAL, "alice"])
def test_service_inconnu(service):
    assert raison(handle_request(fabriquer_requete(service=service), KEYS)) == "service inconnu"


def test_tgt_chiffre_avec_une_autre_cle():
    req = fabriquer_requete(cle_tgt=new_session_key("aes128"))
    assert raison(handle_request(req, KEYS)) == "TGT invalide"


def test_tgt_modifie():
    req = fabriquer_requete()
    raw = bytearray(bytes.fromhex(req["tgt"]))
    raw[20] ^= 0x01
    req["tgt"] = raw.hex()
    assert raison(handle_request(req, KEYS)) == "TGT invalide"


def test_tgt_expire():
    assert raison(handle_request(fabriquer_requete(exp_decalage=-1), KEYS)) == "TGT expiré"


def test_authenticator_avec_une_autre_cle():
    req = fabriquer_requete(cle_auth=new_session_key("aes128"))
    assert raison(handle_request(req, KEYS)) == "authenticator invalide"


def test_authenticator_d_un_autre_client():
    req = fabriquer_requete(client_auth="mallory")
    assert raison(handle_request(req, KEYS)) == "client de l'authenticator différent de celui du TGT"


@pytest.mark.parametrize("decalage", [-config.CLOCK_SKEW - 5, config.CLOCK_SKEW + 5])
def test_timestamp_hors_fenetre(decalage):
    req = fabriquer_requete(ts_decalage=decalage)
    assert raison(handle_request(req, KEYS)) == "timestamp hors de la fenêtre autorisée"
