"""Módulo F — Docker. F2 com cliente Docker simulado; F1/F3 só com a plataforma no ar (SECURAPY_E2E=1)."""

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from scripts.verificar_containers import SERVICOS, status_plataforma, todos_rodando

pytestmark = pytest.mark.docker

E2E = pytest.mark.skipif(os.environ.get("SECURAPY_E2E") != "1", reason="defina SECURAPY_E2E=1 com o compose no ar")


def _conteiner(servico, status):
    labels = {"com.docker.compose.project": "securapy", "com.docker.compose.service": servico}
    return SimpleNamespace(name=f"securapy-{servico}-1", status=status, labels=labels,
                           attrs={"Config": {"Labels": labels}, "State": {"Status": status}})


def _docker_falso(*conteineres):
    cliente = MagicMock()
    cliente.containers.list.return_value = list(conteineres)
    return cliente


def test_f2_tres_servicos_running():
    cliente = _docker_falso(*(_conteiner(s, "running") for s in SERVICOS))
    status = status_plataforma(cliente)
    assert {s["servico"] for s in status} == set(SERVICOS)
    assert all(s["status"] == "running" for s in status)
    assert todos_rodando(status)


def test_f2_detecta_servico_parado():
    cliente = _docker_falso(_conteiner("api", "running"), _conteiner("mongodb", "running"),
                            _conteiner("mysql", "exited"))
    assert not todos_rodando(status_plataforma(cliente))


def test_f2_detecta_servico_ausente():
    cliente = _docker_falso(_conteiner("api", "running"), _conteiner("mongodb", "running"))
    assert not todos_rodando(status_plataforma(cliente))


@E2E
def test_f1_f2_compose_real():
    assert todos_rodando(status_plataforma())


@E2E
def test_f3_api_responde_200():
    import requests
    assert requests.get("http://localhost:5000/api/saude", timeout=5).status_code == 200
