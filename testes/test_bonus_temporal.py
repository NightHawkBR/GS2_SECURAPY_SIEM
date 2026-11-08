"""Bônus — correlação temporal: brute force em janela de tempo, não só contagem total."""

from datetime import datetime, timedelta

import pytest

import orquestrador
from config import settings
from core.detector import (
    detectar_brute_force,
    detectar_brute_force_temporal,
    gerar_alertas_rajada,
)
from core.pipeline import analisar_pasta

pytestmark = pytest.mark.temporal


def _falhas(ip, quantidade, intervalo_segundos, usuario="admin"):
    inicio = datetime(2025, 2, 20, 8, 0, 0)
    return [
        {"timestamp": f"{inicio + timedelta(seconds=i * intervalo_segundos):%Y-%m-%d %H:%M:%S}",
         "fonte": "auth", "tipo": "FAIL", "ip": ip, "detalhes": f"usuario={usuario}"}
        for i in range(quantidade)
    ]


@pytest.fixture
def eventos(eventos_reais):
    return eventos_reais


# ── Detecção ───────────────────────────────────────────────────

def test_rajada_do_atacante(eventos):
    rajada = detectar_brute_force_temporal(eventos)["185.220.101.1"]
    assert rajada["pico"] == 11
    assert rajada["duracao_segundos"] == 39
    assert (rajada["inicio"], rajada["fim"]) == ("2025-02-20 08:15:01", "2025-02-20 08:15:40")
    assert rajada["severidade"] == "ALTA"
    assert {"admin", "root", "test", "sa"} <= rajada["usuarios"]


def test_rajada_no_limite_e_media(eventos):
    rajada = detectar_brute_force_temporal(eventos)["91.240.118.172"]
    assert (rajada["pico"], rajada["severidade"]) == (5, "MEDIA")


def test_poucas_falhas_nao_e_rajada(eventos):
    assert "45.33.32.156" not in detectar_brute_force_temporal(eventos)


def test_mesmas_falhas_espalhadas_nao_sao_rajada():
    """A diferença do bônus: a contagem total acusa, a janela de tempo não."""
    espalhadas = _falhas("203.0.113.7", quantidade=8, intervalo_segundos=600)
    assert "203.0.113.7" in detectar_brute_force(espalhadas)
    assert "203.0.113.7" not in detectar_brute_force_temporal(espalhadas)


def test_janela_menor_desfaz_a_rajada(eventos):
    assert detectar_brute_force_temporal(eventos, janela_segundos=10) == {}
    assert detectar_brute_force_temporal(eventos, janela_segundos=10, limite=4)["185.220.101.1"]["pico"] == 4


def test_rajada_muito_rapida_e_critica():
    rajada = detectar_brute_force_temporal(_falhas("198.51.100.9", quantidade=25, intervalo_segundos=1))
    assert rajada["198.51.100.9"]["severidade"] == "CRITICA"


def test_timestamp_invalido_nao_quebra():
    eventos = _falhas("198.51.100.9", 6, 2)
    eventos.append({"timestamp": "ontem", "fonte": "auth", "tipo": "FAIL", "ip": "198.51.100.9", "detalhes": ""})
    assert detectar_brute_force_temporal(eventos)["198.51.100.9"]["pico"] == 6
    assert detectar_brute_force_temporal([]) == {}


# ── Integração com a plataforma ────────────────────────────────

def test_alerta_no_formato_do_contrato(eventos):
    alerta, *_ = [a for a in gerar_alertas_rajada(detectar_brute_force_temporal(eventos))
                  if a["ip"] == "185.220.101.1"]
    assert alerta["regra_id"] == "T001"
    assert alerta["severidade"] == "ALTA"
    assert alerta["timestamp"] == "2025-02-20 08:15:40"
    assert "11 falhas" in alerta["descricao"]


def test_pipeline_gera_alerta_e_agrava_a_ameaca():
    resultado = analisar_pasta(settings.PASTA_LOGS, settings.ARQUIVO_REGRAS, settings.BLACKLIST)
    assert {a["ip"] for a in resultado["alertas"] if a["regra_id"] == "T001"} == {"185.220.101.1", "91.240.118.172"}
    atacante = next(a for a in resultado["ameacas"] if a["ip"] == "185.220.101.1")
    assert "brute_force_rajada" in atacante["deteccoes"]


def test_rajada_chega_aos_consoles_em_tempo_real(monkeypatch, ambiente_isolado):
    transmitidos = []
    monkeypatch.setattr(orquestrador, "broadcast_alerta", transmitidos.append)
    monkeypatch.setattr(orquestrador.classificar, "pontuar", lambda eventos: [])

    orquestrador.executar_analise(persistir=False)
    rajadas = [a for a in transmitidos if a["regra_id"] == "T001"]
    assert [a["ip"] for a in rajadas] == ["185.220.101.1"]      # só ALTA/CRITICA vão para os consoles
