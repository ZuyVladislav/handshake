# -*- coding: utf-8 -*-
"""
handshake package

Содержит 12 подпакетов chapter01 … chapter12.
После импорта доступна функция run_chapter(n, *args, **kw),
а сами модули можно брать как handshake.chapter03 и т.д.
"""

from importlib import import_module
from types import ModuleType
from typing import Dict

__all__ = ["run_chapter", "CHAPTERS"] + [
    f"chapter{n:02d}" for n in range(1, 13)
]

# ────────────────────────────────────────────────────────────────────
#  Создаём ленивые прокси-объекты: импорт модуля произойдёт при
#  первом обращении, а не сразу при загрузке пакета.
# --------------------------------------------------------------------

def _lazy_import(name: str) -> ModuleType:
    return import_module(name, __package__)

CHAPTERS: Dict[int, ModuleType] = {
    n: _lazy_import(f".chapter{n:02d}") for n in range(1, 13)
}

def run_chapter(n: int, *args, **kwargs):
    """
    Утилита-обёртка:
        >>> handshake.run_chapter(4, X1, X2)
    Эквивалентно:
        >>> from handshake.chapter04 import run
        >>> run(X1, X2)
    """
    if n not in CHAPTERS:
        raise ValueError(f"Номер главы должен быть 1…12, а не {n}")
    return CHAPTERS[n].run(*args, **kwargs)