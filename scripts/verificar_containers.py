"""Confere, via Docker SDK, se os 3 serviços do compose estão "running".  Módulo F · Aula 11

Uso: python scripts/verificar_containers.py   (código de saída 0 = tudo no ar)
"""

import sys

import docker

PROJETO = "securapy"
SERVICOS = ("api", "mongodb", "mysql")


def status_plataforma(cliente=None) -> list[dict]:
    """[{"servico", "nome", "status"}] filtrando pela label com.docker.compose.project=securapy.  [F2]"""
    raise NotImplementedError


def todos_rodando(status) -> bool:
    """True só se cada serviço de SERVICOS aparece com status "running".  [F2]"""
    raise NotImplementedError


def exibir(status) -> None:
    """Tabela alinhada SERVIÇO | CONTÊINER | STATUS, destacando o que não está running."""
    raise NotImplementedError


if __name__ == "__main__":
    try:
        status = status_plataforma()
    except docker.errors.DockerException:
        print("[ERRO] Docker indisponível — o Docker Desktop está aberto?")
        sys.exit(2)
    exibir(status)
    sys.exit(0 if todos_rodando(status) else 1)
