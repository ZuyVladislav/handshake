# -*- coding: utf-8 -*-
"""
handshake.utils
Набор вспомогательных функций: RSA-генерация/шифрование (в т. ч. «длинные»
сообщения), AES-CBC с PKCS#7, KDF, SHA-256, а также единая функция trace()
для сквозного детального журналирования пакетов.

Все функции абсолютно «плоские» – их можно импортировать точечно:
    from handshake.utils import rsa_encrypt_long, sym_encrypt, trace, …
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from typing import List, Dict, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from .config import RSA_KEY_SIZE, AES_BLOCK_LEN  # см. config.py

log = logging.getLogger("crypto.handshake")      # основной лог
# отдельный «шумный» трейсер удобно настроить на DEBUG/TRACE отдельно
tlog = logging.getLogger("crypto.handshake.trace")


# ─────────────────────────────  RSA  ──────────────────────────────
def rsa_gen(bits: int = RSA_KEY_SIZE) -> rsa.RSAPrivateKey:
    """Генерирует приватный RSA-ключ (OEAP, SHA-256)."""
    return rsa.generate_private_key(public_exponent=65537,
                                    key_size=bits,
                                    backend=default_backend())


def rsa_encrypt(pub: rsa.RSAPublicKey, data: bytes) -> bytes:
    return pub.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )


def rsa_decrypt(priv: rsa.RSAPrivateKey, blob: bytes) -> bytes:
    return priv.decrypt(
        blob,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )


# ──────────  «длинное» RSA – дробим на допустимые блоки  ───────────
def _rsa_max_chunk(pub: rsa.RSAPublicKey) -> int:
    key_bytes = pub.key_size // 8
    hlen      = hashes.SHA256().digest_size          # = 32 B
    return key_bytes - 2 * hlen - 2                 # PKCS#1 OAEP формула


def rsa_encrypt_long(pub: rsa.RSAPublicKey, data: bytes) -> List[bytes]:
    """
    Шифрует массив данных «частями», чтобы обойти лимит OAEP-блока.
    Возвращает список ciphertext-блоков.
    """
    max_chunk = _rsa_max_chunk(pub)
    return [rsa_encrypt(pub, data[i:i + max_chunk])
            for i in range(0, len(data), max_chunk)]


def rsa_decrypt_long(priv: rsa.RSAPrivateKey, chunks: List[bytes]) -> bytes:
    """Обратная операция для rsa_encrypt_long()."""
    return b"".join(rsa_decrypt(priv, c) for c in chunks)


# ─────────────────────────────  AES  ───────────────────────────────
def _pkcs7_pad(data: bytes, block: int = AES_BLOCK_LEN) -> bytes:
    pad_len = block - len(data) % block
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES_BLOCK_LEN:
        raise ValueError("Bad PKCS#7 padding")
    return data[:-pad_len]


def sym_encrypt(key: bytes, pt: bytes) -> bytes:
    """
    AES-CBC ⟨IV|ciphertext⟩, где IV прикрепляется впритык.
    """
    iv = secrets.token_bytes(AES_BLOCK_LEN)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(_pkcs7_pad(pt)) + enc.finalize()
    return iv + ct


def sym_decrypt(key: bytes, blob: bytes) -> bytes:
    iv, ct = blob[:AES_BLOCK_LEN], blob[AES_BLOCK_LEN:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    return _pkcs7_unpad(pt)


# ─────────────────────────────  KDF  ───────────────────────────────
def kdf(shared: bytes, info: bytes, ln: int = 32) -> bytes:
    """
    ConcatKDF-Hash (SHA-256).  Применяем для вывода симметричного ключа
    из общего DH-секрета.
    """
    ck = ConcatKDFHash(algorithm=hashes.SHA256(),
                       length=ln,
                       otherinfo=info,
                       backend=default_backend())
    return ck.derive(shared)


# ─────────────────────────────  HASH  ──────────────────────────────
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ───────────────────────  сквозной TRACE-лог  ──────────────────────
def trace(step: str, src: str, dst: str,
          enc: str, payload: Dict[str, Any] | List[Any] | str) -> None:
    """
    Унифицированная точка трассировки всех пакетов.

    • step  – «1.13», «7.18» …   (может быть «?»)
    • src, dst – имена узлов
    • enc  – маркировка слоя:  RSA / DH(A-X1) / RSA-long …
    • payload – либо сам dict/список, либо краткое описание
    """
    if tlog.isEnabledFor(logging.DEBUG):
        # чтобы лог был компактным: показываем только ключи словаря
        if isinstance(payload, dict):
            payload_view = list(payload.keys())
        else:
            payload_view = payload
        tlog.debug("%5s  %s → %s  (%s)  %s",
                   step, src, dst, enc, payload_view)