# -*- coding: utf-8 -*-
"""
handshake.config
Единая «точка правды» для параметров криптографии, IKE-предложений,
идентификаторов узлов и настроек логирования.
"""

from __future__ import annotations
import os
import secrets
import logging
from dataclasses import dataclass
from typing import List

# ────────────────────────── крипто-константы ─────────────────────────
RSA_KEY_SIZE: int      = 4096          # production ≥ 2048
DH_KEY_SIZE: int   = 2048          # production ≥ 2048 (глава-демо ↓ 512)
AES_BLOCK_LEN: int = 16            # байт, для AES-CBC/PKCS#7

# ────────────────────────── IKE-предложения SA ───────────────────────
IKEV2_PROPOSALS = {
    "encryption": ["aes256", "aes192", "aes128"],
    "hash":       ["sha256", "sha1"],
    "dh_group":   [14, 5, 2],          # 2048-, 1536-, 1024-битные группы
}

KEY_LIFETIME = 3600                   # секунд

# ────────────────────────── идентификаторы узлов ─────────────────────
NODE_IDS = {
    "A":  "Node-A-Identifier",
    "B":  "Node-B-Identifier",
    "X1": "Intermediate-X1",
    "X2": "Intermediate-X2",
}

# ────────────────────────── вспом. структуры/утилиты ─────────────────
@dataclass(frozen=True)
class SecurityParameters:
    """Конкретный набор SA-параметров, выбранный в ходе обмена."""
    encryption: str
    hash_algo:  str
    dh_group:   int

def generate_nonce(length: int = 32) -> bytes:
    """Крипто-стойкий nonce."""
    return secrets.token_bytes(length)

# ────────────────────────── базовая настройка логов ───────────────────
def configure_logging(level: int = logging.DEBUG) -> None:
    """
    Вызывается *один раз* в `handshake/main.py` **до** импорта глав,
    чтобы root-логгер был готов раньше первого `trace()/log.debug`.
    """
    logging.basicConfig(
        level   = level,
        format  = "%(asctime)s %(levelname)-8s %(message)s",
        force   = True,           # перезаписываем более ранние конфиги
    )

# ────────────────────────── what gets re-exported ? ───────────────────
__all__: List[str] = [
    "RSA_BITS", "DH_KEY_SIZE", "AES_BLOCK_LEN",
    "IKEV2_PROPOSALS", "KEY_LIFETIME",
    "NODE_IDS", "SecurityParameters",
    "generate_nonce", "configure_logging",
]