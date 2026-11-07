"""Treino do classificador de risco por IP.  Módulo C · Aulas 4 e 12

Dados de treino:
  • IPs reais dos logs, rotulados pelo núcleo (ataque = o detector do 1º semestre gerou ameaça);
  • amostras sintéticas por perfil de comportamento — 7 IPs reais não sustentam validação cruzada.

Uso: python main.py treinar
"""

import json
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_predict, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from config import settings
from core.coletor import carregar_todos_os_logs
from core.detector import detectar_brute_force, detectar_port_scan, gerar_resumo_ameacas, verificar_blacklist
from ml.features import FEATURES, extrair_features
from ml.integridade import registrar_hash

SEMENTE = 42
AMOSTRAS_SINTETICAS = 500
METRICAS = ("precisao", "recall", "f1")


def _blacklist(rng, chance):
    return int(rng.random() < chance)


# perfil → (rótulo, peso, gerador de [falhas_login, portas_distintas, na_blacklist, erros_web])
PERFIS = {
    "usuario_comum":       (0, .45, lambda r: [r.poisson(.6), int(r.random() < .05), 0, r.poisson(.8)]),
    "usuario_erra_senha":  (0, .15, lambda r: [r.integers(2, 6), 0, 0, r.integers(0, 4)]),
    "brute_force":         (1, .12, lambda r: [r.integers(5, 40), r.integers(0, 3), _blacklist(r, .5), r.integers(0, 6)]),
    "port_scan":           (1, .10, lambda r: [r.integers(0, 3), r.integers(3, 25), _blacklist(r, .5), r.integers(0, 3)]),
    "ataque_web":          (1, .10, lambda r: [r.integers(0, 3), r.integers(0, 2), _blacklist(r, .4), r.integers(3, 20)]),
    "ioc_discreto":        (1, .08, lambda r: [r.integers(0, 4), r.integers(0, 3), 1, r.integers(0, 4)]),
}


def gerar_sinteticos(quantidade=AMOSTRAS_SINTETICAS, semente=SEMENTE):
    """Amostras independentes por perfil; total_eventos = atividade suspeita + tráfego normal."""
    rng = np.random.default_rng(semente)
    nomes = list(PERFIS)
    sorteados = rng.choice(nomes, size=quantidade, p=[PERFIS[n][1] for n in nomes])

    X, y = [], []
    for nome in sorteados:
        rotulo, _, gerar = PERFIS[nome]
        falhas, portas, blacklist, erros = gerar(rng)
        X.append([falhas, portas, blacklist, erros, falhas + portas + erros + rng.integers(1, 15)])
        y.append(rotulo)
    return X, y


def rotular_reais(eventos, blacklist):
    """Features dos IPs dos logs + rótulo vindo das detecções do núcleo."""
    ameacas = gerar_resumo_ameacas(
        detectar_brute_force(eventos), detectar_port_scan(eventos), verificar_blacklist(eventos, blacklist)
    )
    atacantes = {ameaca["ip"] for ameaca in ameacas}
    features = extrair_features(eventos, blacklist)
    return list(features.values()), [int(ip in atacantes) for ip in features]


def montar_dataset(eventos, blacklist=settings.BLACKLIST) -> tuple[np.ndarray, np.ndarray]:
    """X (features por IP, ordem de FEATURES) e y (1 = ataque).  [C1]"""
    X_reais, y_reais = rotular_reais(eventos, blacklist)
    X_sint, y_sint = gerar_sinteticos()
    return np.array(X_reais + X_sint, dtype=float), np.array(y_reais + y_sint)


def criar_pipeline() -> Pipeline:
    """StandardScaler + Random Forest (balanceado: em segurança ataques são a minoria).  [C1]"""
    return Pipeline([
        ("escala", StandardScaler()),
        ("modelo", RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=SEMENTE)),
    ])


def avaliar(pipeline, X, y, folds=5) -> dict:
    """Validação cruzada estratificada → média e desvio de precisão, recall e F1 + matriz de confusão.  [C1]"""
    divisao = StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEMENTE)
    notas = cross_validate(pipeline, X, y, cv=divisao, scoring=("precision", "recall", "f1"))
    previstos = cross_val_predict(pipeline, X, y, cv=divisao)

    resultado = {}
    for nome, chave in zip(METRICAS, ("test_precision", "test_recall", "test_f1")):
        resultado[nome] = round(float(notas[chave].mean()), 4)
        resultado[f"{nome}_desvio"] = round(float(notas[chave].std()), 4)
    resultado["matriz_confusao"] = confusion_matrix(y, previstos).tolist()
    resultado["folds"] = folds
    return resultado


def treinar_e_salvar(pasta_logs=settings.PASTA_LOGS, caminho_modelo=settings.MODELO_ML,
                     caminho_hash=settings.HASH_MODELO, caminho_metricas=settings.METRICAS_ML) -> dict:
    """Avalia, treina com tudo, salva com joblib, registra o SHA-256 e grava metricas.json.  [C1][C4]"""
    X, y = montar_dataset(carregar_todos_os_logs(str(pasta_logs)))
    pipeline = criar_pipeline()
    metricas = avaliar(pipeline, X, y)

    pipeline.fit(X, y)
    Path(caminho_modelo).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, caminho_modelo)

    metricas |= {
        "amostras": int(len(y)),
        "ataques": int(y.sum()),
        "features": list(FEATURES),
        "algoritmo": "StandardScaler + RandomForestClassifier",
        "sklearn": sklearn.__version__,
        "treinado_em": datetime.now().isoformat(timespec="seconds"),
        "sha256": registrar_hash(caminho_modelo, caminho_hash),
    }
    Path(caminho_metricas).write_text(json.dumps(metricas, indent=2, ensure_ascii=False), encoding="utf-8")
    return metricas


def exibir_relatorio(metricas):
    (vn, fp), (fn, vp) = metricas["matriz_confusao"]
    print("\n=== Módulo C · Classificador de risco por IP ===")
    print(f"Amostras: {metricas['amostras']} ({metricas['ataques']} ataques) · "
          f"validação cruzada estratificada, {metricas['folds']} folds\n")
    for nome in METRICAS:
        print(f"  {nome:<9} {metricas[nome]:.2f} ± {metricas[f'{nome}_desvio']:.2f}")
    print("\nMatriz de confusão")
    print(f"  {'':<14}{'prev. normal':>13}{'prev. ataque':>13}")
    print(f"  {'real normal':<14}{vn:>13}{fp:>13}")
    print(f"  {'real ataque':<14}{fn:>13}{vp:>13}")
    print(f"\nSHA-256 do modelo: {metricas['sha256']}")


if __name__ == "__main__":
    exibir_relatorio(treinar_e_salvar())
