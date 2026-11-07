"""Carrega o modelo (com verificação de integridade) e pontua o risco de cada IP.  Módulo C"""

import joblib

from config import settings
from core.contratos import Classificacao
from ml.features import extrair_features, vetor_vazio
from ml.integridade import verificar_integridade

LIMIAR_ATAQUE = 0.5
CLASSE_ATAQUE = 1


def carregar_modelo(caminho_modelo=settings.MODELO_ML, caminho_hash=settings.HASH_MODELO):
    """Verifica o SHA-256 ANTES do joblib.load. Divergente → ModeloAdulteradoError.  [C4]"""
    verificar_integridade(caminho_modelo, caminho_hash)
    return joblib.load(caminho_modelo)


def _classificar(vetores: dict[str, list], modelo) -> list[Classificacao]:
    ips = list(vetores)
    coluna = list(modelo.classes_).index(CLASSE_ATAQUE)
    scores = modelo.predict_proba([vetores[ip] for ip in ips])[:, coluna]
    return [
        {"ip": ip, "score": round(float(score), 4), "rotulo": "ataque" if score >= LIMIAR_ATAQUE else "normal"}
        for ip, score in zip(ips, scores)
    ]


def classificar_ip(ip, eventos, modelo=None) -> Classificacao:
    """score = probabilidade de ataque; rotulo = "ataque" se score >= LIMIAR_ATAQUE.  [C2][C3]"""
    modelo = modelo or carregar_modelo()
    features = extrair_features(eventos, settings.BLACKLIST)
    return _classificar({ip: features.get(ip, vetor_vazio(ip, settings.BLACKLIST))}, modelo)[0]


def pontuar(eventos, modelo=None) -> list[Classificacao]:
    """Classifica todos os IPs presentes nos eventos, do maior score para o menor."""
    modelo = modelo or carregar_modelo()
    ranking = _classificar(extrair_features(eventos, settings.BLACKLIST), modelo)
    return sorted(ranking, key=lambda c: c["score"], reverse=True)
