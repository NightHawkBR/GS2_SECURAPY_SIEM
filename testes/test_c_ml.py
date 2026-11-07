"""Módulo C — Machine Learning. Cenários C1–C4 da GS (o modelo é treinado numa pasta temporária)."""

import hashlib
import json
import shutil

import pytest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from config import settings
from core.coletor import carregar_todos_os_logs
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
