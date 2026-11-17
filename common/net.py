"""Envoi et réception des messages JSON sur une socket TCP.

Format sur le fil : 4 octets (longueur du JSON, big-endian) puis le JSON en UTF-8.
TCP est un flux d'octets : sans ce préfixe, le destinataire ne saurait pas
où s'arrête un message.

Ce module fournit aussi :
  - error(reason)                  : construit un message ERROR ;
  - send_request(host, port, msg)  : côté client, une requête -> une réponse ;
  - serve(host, port, handler)     : côté serveur, la boucle accept + un thread
                                     par connexion. Chaque serveur n'a plus qu'à
                                     écrire handler(msg: dict) -> dict.
"""

import json
import socket
import struct
import threading
import time
import traceback
from typing import Callable

MAX_MSG_SIZE = 1024 * 1024  # 1 Mo
CONN_TIMEOUT = 10.0  # secondes d'inactivité avant d'abandonner une connexion
HEADER = struct.Struct(">I")  # entier non signé 32 bits, big-endian


class ProtocolError(Exception):
    """Message reçu invalide (trop gros, pas du JSON, pas un objet...)."""


class ConnectionClosed(ProtocolError):
    """L'autre côté a fermé la connexion avant la fin du message."""


class MessageTooLarge(ProtocolError):
    """Le message dépasse MAX_MSG_SIZE."""


def error(reason: str) -> dict:
    """Construit un message d'erreur du protocole."""
    return {"type": "ERROR", "reason": reason}


def send_msg(sock: socket.socket, msg: dict) -> None:
    """Envoie msg (dictionnaire) en JSON préfixé par sa longueur."""
    payload = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_MSG_SIZE:
        raise MessageTooLarge(f"message de {len(payload)} octets (max {MAX_MSG_SIZE})")
    sock.sendall(HEADER.pack(len(payload)) + payload)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Lit exactement n octets (recv peut en renvoyer moins à chaque appel)."""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(min(remaining, 65536))
        if not chunk:
            raise ConnectionClosed(f"connexion fermée ({n - remaining}/{n} octets reçus)")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_msg(sock: socket.socket) -> dict:
    """Reçoit un message complet et le renvoie sous forme de dictionnaire.

    Lève ConnectionClosed, MessageTooLarge ou ProtocolError.
    """
    (length,) = HEADER.unpack(recv_exact(sock, HEADER.size))
    if length > MAX_MSG_SIZE:
        raise MessageTooLarge(f"message annoncé de {length} octets (max {MAX_MSG_SIZE})")
    payload = recv_exact(sock, length)
    try:
        msg = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("message qui n'est pas du JSON valide") from exc
    if not isinstance(msg, dict):
        raise ProtocolError("le message doit être un objet JSON")
    return msg


def send_request(host: str, port: int, msg: dict, timeout: float = 5.0) -> dict:
    """Côté client : se connecte, envoie msg, attend la réponse, ferme."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        send_msg(sock, msg)
        return recv_msg(sock)


Handler = Callable[[dict], dict]


def log(name: str, text: str) -> None:
    """Affiche une ligne horodatée, préfixée par le nom du programme."""
    print(f"[{time.strftime('%H:%M:%S')}] [{name}] {text}", flush=True)


def _handle_connection(conn: socket.socket, addr, handler: Handler, name: str) -> None:
    conn.settimeout(CONN_TIMEOUT)
    with conn:
        try:
            request = recv_msg(conn)
        except ProtocolError as exc:
            log(name, f"{addr[0]}:{addr[1]} message invalide : {exc}")
            try:
                send_msg(conn, error(f"message invalide : {exc}"))
            except OSError:
                pass
            return
        except OSError as exc:
            log(name, f"{addr[0]}:{addr[1]} erreur réseau : {exc}")
            return

        log(name, f"{addr[0]}:{addr[1]} -> {request.get('type')}")
        try:
            response = handler(request)
        except Exception:  # un bug dans le handler ne doit pas tuer le serveur
            traceback.print_exc()
            response = error("erreur interne du serveur")
        if not isinstance(response, dict):
            response = error("erreur interne du serveur (réponse invalide)")
        log(name, f"{addr[0]}:{addr[1]} <- {response.get('type')}"
                  + (f" ({response.get('reason')})" if response.get("type") == "ERROR" else ""))
        try:
            send_msg(conn, response)
        except OSError as exc:
            log(name, f"{addr[0]}:{addr[1]} réponse non envoyée : {exc}")


def serve_socket(server: socket.socket, handler: Handler, name: str = "serveur") -> None:
    """Boucle d'acceptation sur une socket déjà en écoute.

    Chaque connexion est traitée dans son propre thread : un message reçu,
    handler(message) appelé, la réponse renvoyée, la connexion fermée.
    S'arrête quand la socket d'écoute est fermée.
    """
    # Timeout d'une seconde sur accept() : permet à Ctrl+C d'être pris en
    # compte rapidement, y compris sous Windows.
    server.settimeout(1.0)
    while True:
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break  # socket d'écoute fermée
        threading.Thread(
            target=_handle_connection, args=(conn, addr, handler, name), daemon=True
        ).start()


def serve(host: str, port: int, handler: Handler, name: str = "serveur") -> None:
    """Ouvre une socket TCP sur (host, port) et sert les requêtes jusqu'à Ctrl+C."""
    server = socket.create_server((host, port))
    log(name, f"en écoute sur {host}:{port} (Ctrl+C pour arrêter)")
    try:
        serve_socket(server, handler, name)
    except KeyboardInterrupt:
        log(name, "arrêt")
    finally:
        server.close()
