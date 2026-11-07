"""Features por IP — uma única implementação usada no treino E na classificação.  Módulo C

Reaproveita o detector do 1º semestre: as mesmas contagens que geram alertas viram números para o modelo.
"""

from collections import Counter

from core.detector import detectar_brute_force, detectar_port_scan
from core.regras import extrair_valor

FEATURES = ("falhas_login", "portas_distintas", "na_blacklist", "erros_web", "total_eventos")


def _erro_web(evento):
    if evento.get("fonte") != "web":
        return False
    try:
        return int(extrair_valor(evento.get("detalhes", ""), "status") or 0) >= 400
    except ValueError:
        return False


def vetor_vazio(ip, blacklist):
    """IP sem eventos: só a blacklist pode pesar."""
    return [0, 0, int(ip in blacklist), 0, 0]


def extrair_features(eventos, blacklist) -> dict[str, list[float]]:
    """{ip: [valores na ordem de FEATURES]}  [C1]"""
    falhas = detectar_brute_force(eventos, threshold=1)
    portas = detectar_port_scan(eventos, threshold=1)
    erros = Counter(e["ip"] for e in eventos if _erro_web(e))
    totais = Counter(e["ip"] for e in eventos if e.get("ip"))

    return {
        ip: [
            falhas.get(ip, {}).get("tentativas", 0),
            portas.get(ip, {}).get("quantidade", 0),
            int(ip in blacklist),
            erros[ip],
            total,
        ]
        for ip, total in totais.items()
    }
