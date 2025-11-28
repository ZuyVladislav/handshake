"""Инфраструктура транспортного уровня для узлов handshake."""

from __future__ import annotations

import json
import logging
import pickle
import socket
import struct
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric import rsa

log = logging.getLogger("crypto.handshake.transport")


@dataclass(frozen=True)
class Peer:
    """Описание однорангового узла."""

    name: str
    host: str
    port: int
    pubkey: Optional[rsa.RSAPublicKey] = None


class Transport:
    """Базовый интерфейс транспорта."""

    def send(self, peer_name: str, payload: Any) -> None:  # pragma: no cover - интерфейс
        raise NotImplementedError

    def stop(self) -> None:  # pragma: no cover - интерфейс
        raise NotImplementedError

    # Для RSA-отправки требуется знать открытый ключ адресата.
    def peer_pub(self, peer_name: str) -> rsa.RSAPublicKey:  # pragma: no cover - интерфейс
        raise NotImplementedError


class TcpTransport(Transport):
    """Простейший TCP-транспорт: длина+pickle."""

    def __init__(
        self,
        node: "Node",
        *,
        bind_host: str,
        bind_port: int,
        peers: Mapping[str, Peer],
        login: str,
        password: str,
        auth_db: Mapping[str, str],
    ) -> None:
        from handshake.node import Node  # локальный импорт, чтобы избежать цикла

        if not isinstance(node, Node):  # pragma: no cover - защита от неправильного вызова
            raise TypeError("TcpTransport ожидает экземпляр Node")

        self.node = node
        self.bind_host = bind_host
        self.bind_port = bind_port
        self._peers: Dict[str, Peer] = dict(peers)
        self._login = login
        self._password = password
        self._auth = dict(auth_db)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name=f"tcp-{node.name}", daemon=True)

    # ──────────────────────────────────────────────────────────────
    def start(self) -> None:
        log.info("TcpTransport %s слушает %s:%s", self.node.name, self.bind_host, self.bind_port)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        # открываем loopback, чтобы выйти из accept
        try:
            socket.create_connection((self.bind_host, self.bind_port), timeout=0.2).close()
        except Exception:
            pass
        self._thread.join(timeout=1.0)

    # ──────────────────────────────────────────────────────────────
    def peer_pub(self, peer_name: str) -> rsa.RSAPublicKey:
        peer = self._peers.get(peer_name)
        if peer is None or peer.pubkey is None:
            raise KeyError(f"Неизвестен открытый ключ узла {peer_name}")
        return peer.pubkey

    # ──────────────────────────────────────────────────────────────
    def send(self, peer_name: str, payload: Any) -> None:
        peer = self._peers.get(peer_name)
        if peer is None:
            raise KeyError(f"Неизвестный peer '{peer_name}'")

        message = pickle.dumps({"sender": self.node.name, "payload": payload})
        handshake = json.dumps({
            "login": self._login,
            "password": self._password,
            "sender": self.node.name,
        }).encode()

        def _send() -> None:
            with socket.create_connection((peer.host, peer.port), timeout=5) as sock:
                sock.sendall(struct.pack("!I", len(handshake)))
                sock.sendall(handshake)
                sock.sendall(struct.pack("!I", len(message)))
                sock.sendall(message)

        threading.Thread(target=_send, name=f"tcp-send-{self.node.name}->{peer_name}", daemon=True).start()

    # ──────────────────────────────────────────────────────────────
    def _serve(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.bind_host, self.bind_port))
            srv.listen()
            srv.settimeout(0.5)
            while not self._stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def _handle_client(self, conn: socket.socket) -> None:
        with conn:
            try:
                handshake = self._recv_frame(conn)
                auth = json.loads(handshake.decode())
                if self._auth.get(auth.get("login")) != auth.get("password"):
                    log.warning("отклонено соединение: неверные учётные данные")
                    return

                payload = self._recv_frame(conn)
                message = pickle.loads(payload)
                self.node.inbox.append(message["payload"])
                log.debug(
                    "TcpTransport %s получил сообщение от %s (len=%d)",
                    self.node.name,
                    message.get("sender"),
                    len(payload),
                )
            except Exception as exc:  # pragma: no cover - защита от сетевых проблем
                log.exception("Ошибка в TcpTransport.handle_client: %s", exc)

    @staticmethod
    def _recv_frame(conn: socket.socket) -> bytes:
        header = TcpTransport._recv_exact(conn, 4)
        if not header:
            raise ConnectionError("empty frame")
        (length,) = struct.unpack("!I", header)
        return TcpTransport._recv_exact(conn, length)

    @staticmethod
    def _recv_exact(conn: socket.socket, length: int) -> bytes:
        data = bytearray()
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                raise ConnectionError("соединение закрыто")
            data.extend(chunk)
        return bytes(data)


__all__ = ["Peer", "Transport", "TcpTransport"]

