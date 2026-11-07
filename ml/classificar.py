"""Carrega o modelo (com verificação de integridade) e pontua o risco de cada IP.  Módulo C"""

import joblib

from config import settings
from core.contratos import Classificacao
from ml.features import extrair_features
from ml.integridade import verificar_integridade

LIMIAR_ATAQUE = 0.5


def carregar_modelo(caminho_modelo=settings.MODELO_ML, caminho_hash=settings.HASH_MODELO):
    """Verifica o SHA-256 ANTES do joblib.load. Divergente → ModeloAdulteradoError.  [C4]"""
    raise NotImplementedError


def classificar_ip(ip, eventos, modelo=None) -> Classificacao:
    """score = predict_proba da classe "ataque"; rotulo = "ataque" se score >= LIMIAR_ATAQUE.  [C2][C3]"""
    raise NotImplementedError


def pontuar(eventos, modelo=None) -> list[Classificacao]:
    """Classifica todos os IPs presentes nos eventos, do maior score para o menor."""
    raise NotImplementedError
