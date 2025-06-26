# -*- coding: utf-8 -*-
"""
handshake.multistart  ―  алгоритм множественных стартовых соединений
A  →  X1  →  X2  →  B      (веер параллельных IKE-туннелей)

fanouts = [f1, f2, f3]
    f1 : сколько X1-узлов строится от A          (KD1)
    f2 : сколько X2-узлов строится от каждого X1 (KD2 + Child-SA)
    f3 : сколько параллельных KD3-туннелей от каждого X2 к B
"""

from __future__ import annotations

import logging
from typing import Dict, List

from handshake.node import Node, _sa_store
from handshake.utils import trace
from handshake.chapters import (
    chapter01, chapter02, chapter03, chapter04, chapter05, chapter06,
    chapter07, chapter08, chapter09, chapter10, chapter11, chapter12,
)

log = logging.getLogger("crypto.handshake")

# ───────────────────────── helpers ──────────────────────────
def _mk_children(parent: Node, level: int, fanout: int) -> List[Node]:
    """A → [A_L1_0, …];  X1_L2_0 → [X1_L2_0_L3_0, …]"""
    return [Node(f"{parent.name}_L{level}_{i}") for i in range(fanout)]


def _route_str(nodes: List[Node]) -> str:
    return "→".join(n.name for n in nodes)


# ───────────── обёртки-one-shot над главами ────────────────
def _kd1(a: Node, x1: Node) -> str:
    """Глава 1–2.  Возвращает имя DH-канала KD1(A-X1)."""
    chan = f"{a.name}-{x1.name}"
    chapter01.run(a, x1, chan_name=chan)
    chapter02.run(a, x1, chan_name=chan)
    return chan


def _kd2(a: Node, x1: Node, x2: Node, b: Node, *, chan_a_x1: str) -> str:
    """
    Главы 3–6: KD2(X1-X2) + I2/OK1 + Child-SA.
    Возвращает имя DH-канала KD2(X1-X2).
    """
    chan_x1_x2 = f"{x1.name}-{x2.name}"

    # 3.*  KD2-SA + AUTH
    chapter03.run(x1, x2, chan_name=chan_x1_x2)

    # 4.*  I2 → X2   (OK1(X2) ←)
    ok1_pem = chapter04.run(x1, x2, chan_name=chan_x1_x2)["OK1(X2)"]

    # 5.*  пересылка OK1(X2) инициатору A поверх KD1
    chapter05.run(x1, a, ok1_pem=ok1_pem, chan_name=chan_a_x1)

    # 6.*  Child-SA(A-B) + I6  через X1 → X2
    chapter06.run(
        a, x1, x2, b,
        chan_a_x1=chan_a_x1,
        chan_x1_x2=chan_x1_x2,
    )
    return chan_x1_x2


def _kd3_and_deliver(x2: Node, b: Node, *, chan_name: str = "X2-B") -> None:
    """KD3(chan_name) + доставка пакета Child-SA  (главы 7–8)."""
    chapter07.run(x2, b, chan_name=chan_name)   # IKE SA + AUTH
    chapter08.run(x2, b)                   # пересылаем Child-SA(A-B)


# ────────────────── основной MULTISTART ────────────────────
def multistart_handshake(
    fanouts: List[int] | None = None,
    *,
    debug: bool = False,
) -> None:
    """
    fanouts=[f1,f2,f3] — ширина веера на каждом из трёх уровней.
    """
    if fanouts is None:
        fanouts = [3, 3, 3]

    # подробный trace-лог при --debug
    logging.getLogger("crypto.handshake.trace").setLevel(
        logging.DEBUG if debug else logging.WARNING
    )

    A, B = Node("A"), Node("B")

    # маршрутная карта: имя узла → [A, …, узел]
    routes: Dict[str, List[Node]] = {"A": [A]}

    # ===== Stage-1 : KD1  A ↔ X1 ====================================
    f1 = fanouts[0]
    log.info(">>> Stage-1  fan-out %d", f1)
    x1_nodes = _mk_children(A, 1, f1)

    kd1_chans: Dict[str, str] = {}
    for x1 in x1_nodes:
        kd1_chans[x1.name] = _kd1(A, x1)
        routes[x1.name] = routes["A"] + [x1]

    # ===== Stage-2 : KD2 + Child-SA  X1 ↔ X2 ========================
    f2 = fanouts[1]
    log.info(">>> Stage-2  fan-out %d", f2)
    x2_nodes: List[Node] = []

    for x1 in x1_nodes:
        for x2 in _mk_children(x1, 2, f2):
            x2_nodes.append(x2)
            _kd2(A, x1, x2, B, chan_a_x1=kd1_chans[x1.name])
            routes[x2.name] = routes[x1.name] + [x2]

    # ===== Stage-3 : KD3  X2 ↔ B  (f3 дубликатов) ===================
    f3 = fanouts[2]
    log.info(">>> Stage-3  fan-out %d  (X2-узлов: %d)", f3, len(x2_nodes))

    for x2 in x2_nodes:
        # список RSA-чанков, который глава 6 положила X2 → inbox
        if not x2.inbox:
            log.error("У %s нет пакета Child-SA для B", x2.name)
            continue
        child_chunks: List[bytes] = x2.inbox.pop(0)      # сохраняем
        x2.inbox.append(list(child_chunks))              # вернём оригиналу

        # основной туннель (dup 0) – именно под именем "X2-B"
        _kd3_and_deliver(x2, B, chan_name="X2-B")

        # дубликаты (dup 1 … f3-1)
        for dup in range(1, f3):
            x2_dup = Node(f"{x2.name}_dup{dup}")
            routes[x2_dup.name] = routes[x2.name][:-1] + [x2_dup]

            # кладём КОПИЮ того же списка чанков!
            x2_dup.inbox.append(list(child_chunks))
            _kd3_and_deliver(x2_dup, B)

            trace("route", x2_dup.name, B.name, "final",
                  {"route": _route_str(routes[x2_dup.name])})

    # ===== Завершение : главы 9 – 12 ================================
    if not _sa_store(B.name):  # смотрим, появился ли у B хотя бы один Child-SA
        log.error("B так и не получил Child-SA – остановка")
        return

    # выбираем первый доставленный маршрут
    first_x2 = next(n for n in x2_nodes if routes[n.name][-1] == n)
    first_x1 = routes[first_x2.name][-2]   # предпоследний – это X1

    chapter09.run(B, first_x2, first_x1, A)         # Child-SA(B-A)
    chapter10.run(A, first_x1, first_x2, B)         # AI(A-B)
    chapter11.run(A, first_x1, first_x2, B)         # AI(B-A)
    chapter12.run(A, B)                             # прямой KD4

    log.info("=== multistart DONE  fanouts=%s  доставлено=%d Child-SA ===",
             fanouts, len(_sa_store(B.name)))