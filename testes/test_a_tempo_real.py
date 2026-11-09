"""Módulo A dentro da plataforma: o servidor de alertas sobe junto com a API e a análise sabe se ele está no ar."""

import socket

import pytest

import orquestrador
from alertas import servidor_alertas

pytestmark = pytest.mark.tempo_real


def test_porta_ocupada_nao_derruba_e_avisa(capsys):
    servidor_alertas._no_ar.clear()
    with socket.socket() as ocupante:
        ocupante.bind(("127.0.0.1", 0))
        ocupante.listen()
        servidor_alertas.iniciar_servidor("127.0.0.1", ocupante.getsockname()[1])
    assert "indisponivel" in capsys.readouterr().out
    assert servidor_alertas.esta_no_ar() is False


def test_sem_servidor_a_etapa_tempo_real_falha(ambiente_isolado, monkeypatch):
    transmitidos = []
    monkeypatch.setattr(orquestrador, "broadcast_alerta", transmitidos.append)
    monkeypatch.setattr(servidor_alertas, "esta_no_ar", lambda: False)
    resumo = orquestrador.executar_analise(persistir=False)["resumo"]
    assert resumo["etapas"]["tempo_real"] == "falhou"
    assert resumo["alertas_transmitidos"] == 0 and transmitidos == []


def test_com_servidor_no_ar_os_urgentes_sao_transmitidos(ambiente_isolado, monkeypatch):
    transmitidos = []
    monkeypatch.setattr(orquestrador, "broadcast_alerta", transmitidos.append)
    resumo = orquestrador.executar_analise(persistir=False)["resumo"]
    assert resumo["etapas"]["tempo_real"] == "ok"
    assert resumo["alertas_transmitidos"] == len(transmitidos) == 12
