"""Treino do classificador de risco por IP.  Módulo C · Aulas 4 e 12

Uso: python main.py treinar
"""

import numpy as np
from sklearn.pipeline import Pipeline

from config import settings
from core.coletor import carregar_todos_os_logs
from ml.features import FEATURES, extrair_features
from ml.integridade import registrar_hash


def montar_dataset(eventos, blacklist=settings.BLACKLIST) -> tuple[np.ndarray, np.ndarray]:
    """X (features por IP) e y (1 = ataque, rotulado pelas detecções do núcleo).
    Amplie com amostras sintéticas: 8 IPs reais não sustentam validação cruzada.  [C1]"""
    raise NotImplementedError


def criar_pipeline() -> Pipeline:
    """StandardScaler + classificador (ex.: RandomForest com random_state=42).  [C1]"""
    raise NotImplementedError


def avaliar(pipeline, X, y, folds=5) -> dict[str, float]:
    """Validação cruzada → {"precisao": ..., "recall": ..., "f1": ...} (médias dos folds).  [C1]"""
    raise NotImplementedError


def treinar_e_salvar(pasta_logs=settings.PASTA_LOGS, caminho_modelo=settings.MODELO_ML,
                     caminho_hash=settings.HASH_MODELO, caminho_metricas=settings.METRICAS_ML) -> dict:
    """Avalia, treina com tudo, salva com joblib, registra o SHA-256 e grava metricas.json.  [C1][C4]"""
    raise NotImplementedError


if __name__ == "__main__":
    metricas = treinar_e_salvar()
    print("=== Avaliação (validação cruzada) ===")
    for nome in ("precisao", "recall", "f1"):
        print(f"  {nome:<9} {metricas[nome]:.2f}")
