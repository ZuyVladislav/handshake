from __future__ import annotations
"""
handshake.node — базовый класс узла протокола

• Глобальное (по имени узла) хранилище Child-SA → исчезает проблема с клонами.
• Учёт доставленных пакетов (preview-decrypt + real recv) остаётся.
"""

import json
import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Deque, Dict, Iterable, Optional, Union

if TYPE_CHECKING:
    from handshake.transport import Transport

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dh

from handshake.utils import (
    rsa_gen,
    rsa_encrypt,
    rsa_decrypt,
    sym_encrypt,
    sym_decrypt,
    kdf,
    trace,
)

log = logging.getLogger("crypto.handshake")


# ───────────────────────────- helpers ────────────────────────────────
def _dh_peer_pub(p: int, g: int, y: int) -> dh.DHPublicKey:
    pn = dh.DHParameterNumbers(p, g)
    return dh.DHPublicNumbers(y, pn).public_key(default_backend())


# ──────────────- глобальные репозитории SA и локи ────────────────────
_GLOBAL_SA: Dict[str, Dict[str, Any]] = {}          # node-name → {spi → rec}
_GLOBAL_LOCK: Dict[str, threading.Lock] = {}        # node-name → Lock


def _sa_store(name: str) -> Dict[str, Any]:
    """Возвращает (создавая при необходимости) глобальное SA-хранилище узла."""
    return _GLOBAL_SA.setdefault(name, {})


def _sa_lock(name: str) -> threading.Lock:
    """Возвращает (создавая) глобальный lock под Child-SA конкретного узла."""
    return _GLOBAL_LOCK.setdefault(name, threading.Lock())


# ─────────────────────────────  Node  ────────────────────────────────
class Inbox:
    """Потокобезопасная очередь сообщений узла."""

    def __init__(self) -> None:
        self._items: Deque[Any] = deque()
        self._cv = threading.Condition()

    # --- коллекционный интерфейс -----------------------------------
    def __bool__(self) -> bool:  # bool(queue)
        with self._cv:
            return bool(self._items)

    def __len__(self) -> int:
        with self._cv:
            return len(self._items)

    def __iter__(self) -> Iterable[Any]:
        while True:
            item = self.pop(0)
            yield item

    # --- основные операции -----------------------------------------
    def append(self, item: Any) -> None:
        with self._cv:
            self._items.append(item)
            self._cv.notify()

    def extend(self, items: Iterable[Any]) -> None:
        with self._cv:
            self._items.extend(items)
            self._cv.notify_all()

    def pop(self, index: Optional[int] = None) -> Any:
        """Возвращает элемент с блокировкой до появления данных."""
        with self._cv:
            while not self._items:
                self._cv.wait()
            if index is None:
                return self._items.pop()
            if index == 0:
                return self._items.popleft()
            if index == -1:
                return self._items.pop()
            # random index → придётся материализовать deque в list
            item_list = list(self._items)
            value = item_list.pop(index)
            self._items = deque(item_list)
            return value

    def clear(self) -> None:
        with self._cv:
            self._items.clear()


@dataclass
class Node:
    name: str

    # RSA --------------------------------------------------------------
    rsa_priv: rsa.RSAPrivateKey = field(default_factory=rsa_gen)

    # «Сетевой» буфер
    inbox: Inbox = field(default_factory=Inbox)

    # Транспорт ------------------------------------------------------
    transport: Optional["Transport"] = None

    # DH ---------------------------------------------------------------
    dh_params: Dict[str, dh.DHParameters] = field(default_factory=dict)
    dh_privs:  Dict[str, dh.DHPrivateKey] = field(default_factory=dict)
    dh_peerY:  Dict[str, int]             = field(default_factory=dict)
    dh_shared: Dict[str, bytes]           = field(default_factory=dict)

    # ───────────────────── RSA utils ─────────────────────────────────
    def pub(self):
        return self.rsa_priv.public_key()

    # ───────────────────── DH utils ─────────────────────────────────
    def dh_generate(self, chan: str):
        params = dh.generate_parameters(generator=2, key_size=512,
                                        backend=default_backend())
        priv = params.generate_private_key()
        Y = priv.public_key().public_numbers().y
        self.dh_params[chan] = params
        self.dh_privs [chan] = priv
        return params.parameter_numbers().p, params.parameter_numbers().g, Y

    def dh_set_peer(self, chan: str, peerY: int):
        p = self.dh_params[chan].parameter_numbers().p
        g = self.dh_params[chan].parameter_numbers().g
        shared = self.dh_privs[chan].exchange(_dh_peer_pub(p, g, peerY))
        self.dh_peerY [chan] = peerY
        self.dh_shared[chan] = shared
        return shared

    def dh_key(self, chan: str, ln: int = 32):
        if chan not in self.dh_shared:
            raise RuntimeError(f"DH-канал '{chan}' не установлен у {self.name}")
        return kdf(self.dh_shared[chan], info=chan.encode(), ln=ln)

    # ─────────────────── Child-SA API ────────────────────────────────
    def handle_payload(self, payload: Dict[str, Any]) -> None:
        spi = self._extract_and_store_sa(payload)
        if spi:
            self._record_sa_packet(payload, spi)

    # --- internal ----------------------------------------------------
    def _extract_and_store_sa(self, payload: Dict[str, Any]) -> Optional[str]:
        sa_blob: Optional[Any] = None
        for key in ("SA", "ChildSA", "child_sa"):
            if key in payload:
                sa_blob = payload[key]
                break
        if isinstance(sa_blob, dict) and "ChildSA" in sa_blob:
            sa_blob = sa_blob["ChildSA"]

        if sa_blob is None:
            return None

        spi = self._accept_sa(sa_blob)
        if spi:
            log.info("Child-SA принят  SPI=%s", spi)
        return spi

    def _accept_sa(self, blob: Union[Dict[str, Any], str]) -> Optional[str]:
        if isinstance(blob, dict):
            spi = blob.get("spi") or blob.get("SPI")
            if not spi:
                log.error("Неверный SA-blob (нет spi) → %s", blob)
                return None
        else:
            spi = str(blob)
            blob = {"spi": spi}

        store = _sa_store(self.name)
        with _sa_lock(self.name):
            store.setdefault(spi, {"spi": spi, "packets": []}).update(blob)
        return spi

    def _record_sa_packet(self, payload: Dict[str, Any], spi: Optional[str] = None):
        store = _sa_store(self.name)
        with _sa_lock(self.name):
            if not store:
                return
            if spi is None:
                spi = next(reversed(store))
            store[spi]["packets"].append(payload)

    # Для проверок симулятора
    def has_child_sa(self, spi: str) -> bool:
        return spi in _sa_store(self.name)

    # ───────────────── «сетевые» слои ────────────────────────────────
    def attach_transport(self, transport: "Transport") -> None:
        """Привязывает внешний транспорт к узлу."""
        self.transport = transport

    # --- helpers -----------------------------------------------------
    def _deliver(self, dst: Union["Node", str], blob: Any) -> None:
        if isinstance(dst, Node):
            dst.inbox.append(blob)
        else:
            if self.transport is None:
                raise RuntimeError(
                    f"У узла {self.name} не настроен транспорт для отправки {dst}"
                )
            self.transport.send(dst, blob)

    # --- RSA ---------------------------------------------------------
    def send_rsa(self, dst: Union["Node", str], payload: Dict[str, Any], step: str = "?"):
        pub_key = dst.pub() if isinstance(dst, Node) else self.transport.peer_pub(dst)
        blob = rsa_encrypt(pub_key, json.dumps(payload).encode())
        self._deliver(dst, blob)
        dst_name = dst.name if isinstance(dst, Node) else dst
        trace(step, self.name, dst_name, "RSA-send", payload)

    def recv_rsa(self) -> Dict[str, Any]:
        blob = self.inbox.pop(0)
        payload = json.loads(rsa_decrypt(self.rsa_priv, blob))
        self.handle_payload(payload)
        return payload

    # --- DH ----------------------------------------------------------
    def send_sym(self, chan: str, dst: Union["Node", str],
                 payload: Dict[str, Any], step: str = "?"):
        cipher = sym_encrypt(self.dh_key(chan), json.dumps(payload).encode())
        self._deliver(dst, cipher)
        dst_name = dst.name if isinstance(dst, Node) else dst
        trace(step, self.name, dst_name, f"DH({chan})-send", payload)

        # preview-decrypt на стороне dst, чтобы сразу отметить доставку
        if isinstance(dst, Node):
            try:
                plain = sym_decrypt(dst.dh_key(chan), cipher)
                dst._record_sa_packet(json.loads(plain))
            except Exception:
                pass

    def recv_sym(self, chan: str) -> Dict[str, Any]:
        cipher = self.inbox.pop(0)
        plain = sym_decrypt(self.dh_key(chan), cipher)
        payload = json.loads(plain)
        self._record_sa_packet(payload)
        trace("?", self.name, self.name, f"DH({chan})-recv", payload)
        return payload

    # ────────────────── debug string ────────────────────────────────
    def __repr__(self):
        return f"<Node {self.name}>"