"""Integridade do modelo (OWASP A08): um .pkl executa código ao ser carregado — só carregue se o hash conferir."""

import hashlib
from pathlib import Path


class ModeloAdulteradoError(Exception):
    """SHA-256 do .pkl diferente do registrado no treino."""


def calcular_sha256(caminho) -> str:
    """Hash hexadecimal do arquivo, lido em blocos (hashlib — 1º sem).  [C4]"""
    raise NotImplementedError


def registrar_hash(caminho_modelo, caminho_hash) -> str:
    """Calcula e grava o hash ao lado do modelo. Retorna o hash."""
    raise NotImplementedError


def verificar_integridade(caminho_modelo, caminho_hash) -> None:
    """Hash divergente ou .sha256 ausente → ModeloAdulteradoError.  [C4]"""
    raise NotImplementedError
