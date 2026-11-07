"""Bônus (+0,30): Isolation Forest sobre as métricas por IP — encontra o que as regras não conhecem."""

from sklearn.ensemble import IsolationForest

from ml.features import extrair_features


def detectar_anomalias(eventos, blacklist, contaminacao=0.25) -> list[str]:
    """IPs marcados com -1 pelo IsolationForest(random_state=42) — Aula 4, seção 4.6."""
    raise NotImplementedError
