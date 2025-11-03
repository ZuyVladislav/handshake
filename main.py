# -*- coding: utf-8 -*-
"""
handshake.main  –  точка входа

    python -m handshake.main               # классический один маршрут
    python -m handshake.main --multi 3,3,3 # multistart 3×3×3
    python -m handshake.main --multi 3,3,3 --debug
"""

from __future__ import annotations

import argparse
import logging

from handshake.node import Node
from handshake.utils import sha256
from handshake.chapters import (
    chapter01, chapter02, chapter03, chapter04, chapter05, chapter06,
    chapter07, chapter08, chapter09, chapter10, chapter11, chapter12,
)
from handshake.multistart import multistart_handshake

# ──────────────────────────── CLI ────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("--multi", nargs=1,
                    help="fan-outs, например 3,3,3  →  27 маршрутов")
parser.add_argument("--debug", action="store_true",
                    help="уровень логирования DEBUG + TRACE")
parser.add_argument("--config", help="путь к config.json|yaml с сетью")
parser.add_argument("--node", help="имя узла для сетевого режима")
args = parser.parse_args()

logging.basicConfig(
    level=logging.DEBUG if args.debug else logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    force=True,
)
# подавим трассировочный шум, если не --debug
if not args.debug:
    logging.getLogger("crypto.handshake.trace").setLevel(logging.WARNING)
log = logging.getLogger("crypto.handshake")


# ───────────────────── classic single route ──────────────────
def demo_handshake() -> None:
    log.info(">>> demo_handshake() стартовал")
    A, X1, X2, B = Node("A"), Node("X1"), Node("X2"), Node("B")

    chapter01.run(A, X1);         chapter02.run(A, X1)
    chapter03.run(X1, X2);        ok1 = chapter04.run(X1, X2)["OK1(X2)"]
    chapter05.run(X1, A, ok1_pem=ok1)
    chapter06.run(A, X1, X2, B)
    chapter07.run(X2, B);         chapter08.run(X2, B)
    chapter09.run(B, X2, X1, A);  chapter10.run(A, X1, X2, B)
    chapter11.run(A, X1, X2, B);  chapter12.run(A, B)

    log.info("\n=== SHA-256 общих DH-секретов ===")
    for chan, left, right in [("A-X1", A, X1), ("X1-X2", X1, X2),
                              ("X2-B", X2, B), ("A-B", A, B)]:
        h = sha256(left.dh_shared.get(chan, b"")) if chan in left.dh_shared else "—"
        log.info("%-6s : %s", chan, h)


# ────────────────────────── main ─────────────────────────────
if __name__ == "__main__":
    if args.node:
        if not args.config:
            parser.error("--node требует указать --config")
        from handshake.netconfig import load_config
        from handshake.transport import TcpTransport
        from handshake.node import Node

        cfg = load_config(args.config)
        node_cfg = cfg.node(args.node)

        node = Node(node_cfg.name)
        peers = cfg.peers_for(node_cfg.name)
        transport = TcpTransport(
            node,
            bind_host=node_cfg.host,
            bind_port=node_cfg.port,
            peers=peers,
            login=node_cfg.credentials.login,
            password=node_cfg.credentials.password,
            auth_db=cfg.auth_db(),
        )
        node.attach_transport(transport)
        transport.start()
        log.info("Узел %s запущен, ожидание сообщений (Ctrl+C для выхода)", node.name)

        try:
            while True:
                payload = node.inbox.pop(0)
                log.info("Получено сообщение len=%s", len(payload) if hasattr(payload, "__len__") else type(payload))
        except KeyboardInterrupt:
            log.info("Остановка узла %s", node.name)
        finally:
            transport.stop()
    elif args.multi:
        fanouts = [int(x) for x in args.multi[0].split(",")]
        log.info("Запуск multistart (handshake)  fanouts=%s", fanouts)
        multistart_handshake(fanouts=fanouts, debug=args.debug)
    else:
        if args.config:
            log.warning("--config применён без --node; используется локальный демо-режим")
        demo_handshake()