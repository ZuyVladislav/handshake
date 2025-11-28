"""Загрузка сетевой конфигурации для handshake."""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, MutableMapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from handshake.transport import Peer


@dataclass
class NodeCredentials:
    login: str
    password: str


@dataclass
class NodeConfig:
    name: str
    host: str
    port: int
    credentials: NodeCredentials
    neighbors: Dict[str, str]  # neighbor name → ref in peers
    public_key_pem: str | None = None

    def public_key(self) -> rsa.RSAPublicKey | None:
        if self.public_key_pem is None:
            return None
        return serialization.load_pem_public_key(self.public_key_pem.encode())


@dataclass
class NetworkConfig:
    nodes: Dict[str, NodeConfig]

    def node(self, name: str) -> NodeConfig:
        return self.nodes[name]

    def peers_for(self, name: str) -> Mapping[str, Peer]:
        node = self.node(name)
        peers: MutableMapping[str, Peer] = {}
        for peer_name, ref in node.neighbors.items():
            peer_cfg = self.nodes[ref]
            peers[peer_name] = Peer(
                name=peer_cfg.name,
                host=peer_cfg.host,
                port=peer_cfg.port,
                pubkey=peer_cfg.public_key(),
            )
        return peers

    def auth_db(self) -> Mapping[str, str]:
        return {cfg.credentials.login: cfg.credentials.password for cfg in self.nodes.values()}


def _load_json(path: pathlib.Path) -> Dict[str, object]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_yaml(path: pathlib.Path) -> Dict[str, object]:
    try:
        import yaml  # type: ignore
    except Exception as exc:  # pragma: no cover - модуль может отсутствовать
        raise RuntimeError("Для чтения YAML требуется пакет PyYAML") from exc

    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_config(path: str | pathlib.Path) -> NetworkConfig:
    p = pathlib.Path(path)
    data = _load_yaml(p) if p.suffix.lower() in {".yaml", ".yml"} else _load_json(p)

    raw_nodes = data.get("nodes")
    if not isinstance(raw_nodes, Iterable):
        raise ValueError("config.nodes должен быть массивом")

    nodes: Dict[str, NodeConfig] = {}
    for entry in raw_nodes:
        if not isinstance(entry, Mapping):
            raise ValueError("описание узла должно быть объектом")
        name = str(entry["name"])
        creds_raw = entry.get("credentials") or {}
        credentials = NodeCredentials(
            login=str(creds_raw.get("login")),
            password=str(creds_raw.get("password")),
        )
        neighbors = {
            str(alias): str(target)
            for alias, target in (entry.get("neighbors") or {}).items()
        }
        nodes[name] = NodeConfig(
            name=name,
            host=str(entry.get("host", "127.0.0.1")),
            port=int(entry.get("port", 0)),
            credentials=credentials,
            neighbors=neighbors,
            public_key_pem=entry.get("public_key"),
        )

    return NetworkConfig(nodes=nodes)


__all__ = ["NodeConfig", "NetworkConfig", "NodeCredentials", "load_config"]

