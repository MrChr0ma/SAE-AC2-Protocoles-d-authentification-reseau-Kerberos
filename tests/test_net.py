import socket
import struct
import threading

import pytest

from common import net
from common.net import (
    ConnectionClosed,
    MessageTooLarge,
    ProtocolError,
    recv_msg,
    send_msg,
    send_request,
)


@pytest.fixture
def pair():
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


def test_aller_retour(pair):
    a, b = pair
    msg = {"type": "AS_REQ", "client": "alice", "accents": "éàü", "n": 1.5}
    send_msg(a, msg)
    assert recv_msg(b) == msg


def test_plusieurs_messages_a_la_suite(pair):
    a, b = pair
    for i in range(5):
        send_msg(a, {"i": i})
    assert [recv_msg(b)["i"] for _ in range(5)] == list(range(5))


def test_gros_message_sous_la_limite():
    """Un message proche de la limite arrive entier (recv_exact boucle bien)."""
    a, b = socket.socketpair()
    msg = {"data": "x" * (net.MAX_MSG_SIZE - 100)}
    t = threading.Thread(target=send_msg, args=(a, msg))
    t.start()
    assert recv_msg(b) == msg
    t.join()
    a.close()
    b.close()


def test_message_trop_gros_refuse_a_l_envoi(pair):
    a, _ = pair
    with pytest.raises(MessageTooLarge):
        send_msg(a, {"data": "x" * net.MAX_MSG_SIZE})


def test_message_trop_gros_refuse_a_la_reception(pair):
    a, b = pair
    a.sendall(struct.pack(">I", net.MAX_MSG_SIZE + 1))
    with pytest.raises(MessageTooLarge):
        recv_msg(b)


def test_connexion_fermee(pair):
    a, b = pair
    a.sendall(struct.pack(">I", 10) + b"abc")
    a.close()
    with pytest.raises(ConnectionClosed):
        recv_msg(b)


@pytest.mark.parametrize("payload", [b"pas du json", b"[1, 2]"])
def test_contenu_invalide(pair, payload):
    a, b = pair
    a.sendall(struct.pack(">I", len(payload)) + payload)
    with pytest.raises(ProtocolError):
        recv_msg(b)


def test_error():
    assert net.error("ticket expiré") == {"type": "ERROR", "reason": "ticket expiré"}


@pytest.fixture
def server():
    """Lance serve_socket sur un port libre avec un handler d'écho."""
    def handler(msg):
        if msg.get("type") == "BUG":
            raise RuntimeError("bug simulé")
        return {"type": "ECHO", "recu": msg}

    sock = socket.create_server(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    t = threading.Thread(target=net.serve_socket, args=(sock, handler, "test"), daemon=True)
    t.start()
    yield port
    sock.close()
    t.join(timeout=3)


def test_serve_et_send_request(server):
    rep = send_request("127.0.0.1", server, {"type": "PING"})
    assert rep == {"type": "ECHO", "recu": {"type": "PING"}}


def test_serve_connexions_concurrentes(server):
    results = []

    def worker(i):
        results.append(send_request("127.0.0.1", server, {"type": "PING", "i": i})["recu"]["i"])

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == list(range(20))


def test_serve_survit_a_un_bug_du_handler(server):
    rep = send_request("127.0.0.1", server, {"type": "BUG"})
    assert rep["type"] == "ERROR"
    assert send_request("127.0.0.1", server, {"type": "PING"})["type"] == "ECHO"
