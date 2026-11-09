"""Módulo C — Machine Learning. Cenários C1–C4 da GS (o modelo é treinado numa pasta temporária)."""

import hashlib
import json
import shutil

import pytest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

import orquestrador
from config import settings
from core.coletor import carregar_todos_os_logs
from db import mongo_repo
from ml.anomalias import detectar_anomalias
from ml.classificar import carregar_modelo, classificar_ip, pontuar
from ml.features import FEATURES, extrair_features
from ml.integridade import ModeloAdulteradoError, calcular_sha256, verificar_integridade
from ml.treinar import criar_pipeline, treinar_e_salvar

pytestmark = pytest.mark.ml


@pytest.fixture(scope="module")
def artefatos(tmp_path_factory):
    pasta = tmp_path_factory.mktemp("modelo")
    caminhos = {
        "caminho_modelo": pasta / "modelo.pkl",
        "caminho_hash": pasta / "modelo.sha256",
        "caminho_metricas": pasta / "metricas.json",
    }
    metricas = treinar_e_salvar(settings.PASTA_LOGS, **caminhos)
    return metricas, caminhos


@pytest.fixture(scope="module")
def modelo(artefatos):
    _, caminhos = artefatos
    return carregar_modelo(caminhos["caminho_modelo"], caminhos["caminho_hash"])


@pytest.fixture(scope="module")
def eventos():
    return carregar_todos_os_logs(str(settings.PASTA_LOGS))


def test_features_por_ip(eventos):
    features = extrair_features(eventos, settings.BLACKLIST)
    atacante = dict(zip(FEATURES, features["185.220.101.1"]))
    assert len(features["185.220.101.1"]) == len(FEATURES)
    assert atacante["falhas_login"] == 11
    assert atacante["portas_distintas"] == 7
    assert atacante["na_blacklist"] == 1
    assert dict(zip(FEATURES, features["192.168.1.10"]))["na_blacklist"] == 0


def test_pipeline_com_scaler():
    pipeline = criar_pipeline()
    assert isinstance(pipeline, Pipeline)
    assert any(isinstance(etapa, StandardScaler) for _, etapa in pipeline.steps)


def test_c1_relatorio_de_metricas(artefatos):
    metricas, caminhos = artefatos
    for nome in ("precisao", "recall", "f1"):
        assert 0.0 <= metricas[nome] <= 1.0
    assert json.loads(caminhos["caminho_metricas"].read_text(encoding="utf-8"))["f1"] == metricas["f1"]


def test_c2_atacante_conhecido(modelo, eventos):
    resultado = classificar_ip("185.220.101.1", eventos, modelo)
    assert resultado["rotulo"] == "ataque"
    assert resultado["score"] >= 0.7


def test_c3_trafego_interno(modelo, eventos):
    resultado = classificar_ip("192.168.1.10", eventos, modelo)
    assert resultado["rotulo"] == "normal"
    assert resultado["score"] < 0.5


def test_pontuar_ordena_por_risco(modelo, eventos):
    ranking = pontuar(eventos, modelo)
    scores = [c["score"] for c in ranking]
    assert scores == sorted(scores, reverse=True)
    assert {c["ip"] for c in ranking} == {e["ip"] for e in eventos}


def test_c4_hash_confere(artefatos):
    _, caminhos = artefatos
    modelo_pkl = caminhos["caminho_modelo"]
    assert calcular_sha256(modelo_pkl) == hashlib.sha256(modelo_pkl.read_bytes()).hexdigest()
    verificar_integridade(modelo_pkl, caminhos["caminho_hash"])


def test_c4_modelo_alterado_nao_carrega(artefatos, tmp_path):
    _, caminhos = artefatos
    adulterado = tmp_path / "modelo.pkl"
    adulterado.write_bytes(caminhos["caminho_modelo"].read_bytes() + b"\x00")
    hash_original = shutil.copy(caminhos["caminho_hash"], tmp_path / "modelo.sha256")
    with pytest.raises(ModeloAdulteradoError):
        carregar_modelo(adulterado, hash_original)


def test_c4_sem_hash_registrado_nao_carrega(artefatos, tmp_path):
    _, caminhos = artefatos
    copia = shutil.copy(caminhos["caminho_modelo"], tmp_path / "modelo.pkl")
    with pytest.raises(ModeloAdulteradoError):
        carregar_modelo(copia, tmp_path / "inexistente.sha256")


# ── Bônus: Isolation Forest ────────────────────────────────────

def test_bonus_anomalias_destacam_o_atacante(eventos):
    anomalos = detectar_anomalias(eventos, settings.BLACKLIST)
    assert anomalos[0] == "185.220.101.1"
    assert "192.168.1.10" not in anomalos


def test_bonus_anomalias_sem_dados():
    assert detectar_anomalias([], settings.BLACKLIST) == []


# ── C3: o score do ML ordena o que o analista vê ───────────────

IPS_ANOMALOS = ["185.220.101.1", "91.240.118.172"]


@pytest.fixture
def analise(mongo_fake, ambiente_isolado, monkeypatch):
    monkeypatch.setattr(orquestrador, "broadcast_alerta", lambda alerta: None)
    return orquestrador.executar_analise()


def test_c3_todo_alerta_gravado_tem_score_e_anomalia(analise, mongo_fake):
    alertas = mongo_fake[mongo_repo.ALERTAS]
    assert alertas.count_documents({"score": {"$type": "number"}, "anomalia": {"$type": "bool"}}) == 33
    assert analise["resumo"]["etapas"]["anomalias"] == "ok"


def test_c3_ameacas_vem_do_maior_risco_para_o_menor(analise):
    chaves = [(a["score"], a["pontuacao"]) for a in mongo_repo.listar_ameacas()]
    assert chaves == sorted(chaves, reverse=True)
    assert mongo_repo.listar_ameacas()[0]["ip"] == "185.220.101.1"


def test_c3_api_ordena_alertas_por_risco(cliente, analise):
    mongo_repo.inserir_alerta({"timestamp": "2030-01-01 00:00:00", "regra_id": "MANUAL", "regra_nome": "Manual",
                               "severidade": "BAIXA", "ip": "203.0.113.7", "descricao": "sem score"})
    por_data = cliente.get("/api/alertas?tamanho=1").get_json()["itens"][0]
    por_risco = cliente.get("/api/alertas?ordenar=risco&tamanho=100").get_json()["itens"]
    assert por_data["ip"] == "203.0.113.7"
    assert por_risco[0]["score"] == 1.0 and por_risco[-1]["ip"] == "203.0.113.7"


def test_c3_rota_de_ameacas(cliente, analise):
    itens = cliente.get("/api/ameacas").get_json()["itens"]
    assert [a["ip"] for a in itens][0] == "185.220.101.1"
    assert all({"score", "rotulo_ml", "anomalia", "deteccoes"} <= a.keys() for a in itens)


def test_c3_nova_analise_atualiza_alertas_antigos(mongo_fake, ambiente_isolado, monkeypatch):
    monkeypatch.setattr(orquestrador, "broadcast_alerta", lambda alerta: None)
    mongo_repo.inserir_alerta({"timestamp": "2025-02-19 10:00:00", "regra_id": "MANUAL", "regra_nome": "Antigo",
                               "severidade": "ALTA", "ip": "185.220.101.1", "descricao": "de antes do ML"})
    orquestrador.executar_analise()
    antigo = mongo_fake[mongo_repo.ALERTAS].find_one({"regra_id": "MANUAL"})
    assert antigo["score"] == 1.0 and antigo["anomalia"] is True


def test_bonus_anomalias_entram_na_plataforma(cliente, analise):
    assert analise["resumo"]["ips_anomalos"] == IPS_ANOMALOS
    assert cliente.get("/api/ip/185.220.101.1").get_json()["anomalia"] is True
    assert cliente.get("/api/ip/45.33.32.156").get_json()["anomalia"] is False
