"""Bônus (+0,30): Isolation Forest sobre as métricas por IP — sem rótulos, acha o que foge do padrão.  Aula 4 · 4.6

Uso: python -m ml.anomalias
"""

from sklearn.ensemble import IsolationForest

from config import settings
from core.coletor import carregar_todos_os_logs
from ml.features import extrair_features

SEMENTE = 42


def detectar_anomalias(eventos, blacklist, contaminacao=0.25) -> list[str]:
    """IPs marcados com -1 pelo IsolationForest, do mais anômalo para o menos."""
    features = extrair_features(eventos, blacklist)
    if len(features) < 2:
        return []

    ips = list(features)
    X = [features[ip] for ip in ips]
    detector = IsolationForest(contamination=contaminacao, random_state=SEMENTE).fit(X)

    marcados = zip(ips, detector.predict(X), detector.decision_function(X))
    return [ip for ip, rotulo, _ in sorted(marcados, key=lambda m: m[2]) if rotulo == -1]


if __name__ == "__main__":
    eventos = carregar_todos_os_logs(str(settings.PASTA_LOGS))
    print("\n=== Anomalias (Isolation Forest) ===")
    for posicao, ip in enumerate(detectar_anomalias(eventos, settings.BLACKLIST), start=1):
        print(f"  {posicao}. {ip}")
