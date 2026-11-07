"""Features por IP — uma única implementação usada no treino E na classificação.  Módulo C"""

FEATURES = ("falhas_login", "portas_distintas", "na_blacklist", "erros_web", "total_eventos")


def extrair_features(eventos, blacklist) -> dict[str, list[float]]:
    """{ip: [valores na ordem de FEATURES]}. Reaproveite core.detector / core.regras.  [C1]"""
    raise NotImplementedError
