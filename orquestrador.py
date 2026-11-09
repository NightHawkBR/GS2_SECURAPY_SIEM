"""Fluxo ponta a ponta (GS §4): núcleo → ML → anomalias → enriquecimento → persistência → tempo real.

Cada etapa é isolada: módulo pendente ou serviço fora do ar vira status no resumo,
nunca derruba a análise. Usado pelo POST /api/analisar e pelo `python main.py analisar`.
"""

import logging

from alertas import servidor_alertas
from alertas.servidor_alertas import broadcast_alerta
from config import settings
from core.coletor import carregar_log, carregar_todos_os_logs, identificar_fonte
from core.contratos import serializavel
from core.enriquecimento import carregar_cache, enriquecer_alertas
from core.pipeline import analisar_eventos
from core.regras import carregar_regras
from db import mongo_repo
from ml import classificar
from ml.anomalias import detectar_anomalias

log = logging.getLogger("securapy.orquestrador")


def resolver_caminho_log(caminho):
    """Aceita apenas caminhos dentro de PASTA_LOGS — o valor pode vir da API (path traversal)."""
    base = settings.PASTA_LOGS.resolve()
    alvo = (base / str(caminho)).resolve()
    if alvo != base and base not in alvo.parents:
        raise ValueError("caminho fora da pasta de logs")
    if not alvo.exists():
        raise FileNotFoundError("log inexistente")
    return alvo


def carregar_eventos(caminho=None):
    alvo = resolver_caminho_log(caminho) if caminho else settings.PASTA_LOGS
    if alvo.is_dir():
        return carregar_todos_os_logs(str(alvo))
    if (fonte := identificar_fonte(alvo.name)) is None:
        raise ValueError("fonte de log desconhecida")
    return carregar_log(str(alvo), fonte)


def _etapa(status, nome, funcao, *args, padrao=None):
    try:
        resultado = funcao(*args)
        status[nome] = "ok"
        return resultado
    except NotImplementedError:
        status[nome] = "pendente"
    except Exception as erro:
        log.warning("etapa %s falhou: %s", nome, type(erro).__name__)   # só o tipo: nada de URI/segredo no log
        status[nome] = "falhou"
    return padrao


def _prioridades(classificacoes, anomalos):
    """{ip: score, rótulo do ML e marca do Isolation Forest} — o que ordena alertas e ameaças.  [C3]"""
    prioridades = {c["ip"]: {"score": c["score"], "rotulo_ml": c["rotulo"], "anomalia": c["ip"] in anomalos}
                   for c in classificacoes}
    for ip in set(anomalos) - prioridades.keys():
        prioridades[ip] = {"score": None, "rotulo_ml": None, "anomalia": True}
    return prioridades


def _aplicar_prioridades(ameacas, alertas, prioridades):
    vazio = {"score": None, "rotulo_ml": None, "anomalia": False}
    for item in (*ameacas, *alertas):
        item.update(prioridades.get(item["ip"], vazio))
    return sorted(ameacas, key=lambda a: (a["score"] or 0, a["pontuacao"]), reverse=True)


def _persistir(eventos, alertas, ameacas, prioridades):
    mongo_repo.criar_indices()
    mongo_repo.salvar_eventos(eventos)
    mongo_repo.salvar_alertas(alertas)
    mongo_repo.atualizar_prioridade(prioridades)
    mongo_repo.salvar_ameacas(ameacas)


def _transmitir(alertas):
    if not servidor_alertas.esta_no_ar():
        raise ConnectionError("servidor de alertas fora do ar")
    urgentes = [a for a in alertas if a["severidade"] in settings.ALERTAS_TEMPO_REAL]
    for alerta in urgentes:
        broadcast_alerta(alerta)
    return len(urgentes)


def executar_analise(caminho=None, eventos=None, *, persistir=True, transmitir=True):
    """Roda a plataforma inteira. Retorna {"resumo", "eventos", "alertas", "ameacas"}."""
    eventos = carregar_eventos(caminho) if eventos is None else eventos
    nucleo = analisar_eventos(
        eventos, carregar_regras(settings.ARQUIVO_REGRAS), settings.BLACKLIST,
        janela_segundos=settings.BRUTE_FORCE_JANELA_SEGUNDOS,
        limite_rajada=settings.BRUTE_FORCE_LIMITE_JANELA,
    )
    status = {"nucleo": "ok"}

    classificacoes = _etapa(status, "ml", classificar.pontuar, eventos, padrao=[])
    anomalos = _etapa(status, "anomalias", detectar_anomalias, eventos, settings.BLACKLIST, padrao=[])
    prioridades = _prioridades(classificacoes, anomalos)
    ameacas = serializavel(_aplicar_prioridades(nucleo["ameacas"], nucleo["alertas"], prioridades))

    # geolocalização vem do MongoDB e consultas novas são gravadas lá; sem banco, só a carga inicial em memória
    cache_geo = mongo_repo.CacheGeolocalizacao() if persistir else carregar_cache(settings.ARQUIVO_CACHE_GEO)
    _etapa(status, "enriquecimento", enriquecer_alertas, nucleo["alertas"], cache_geo)

    if persistir:
        _etapa(status, "persistencia", _persistir, eventos, nucleo["alertas"], ameacas, prioridades)
    transmitidos = _etapa(status, "tempo_real", _transmitir, nucleo["alertas"], padrao=0) if transmitir else 0

    resumo = {
        "total_eventos": len(eventos),
        "total_alertas": len(nucleo["alertas"]),
        "total_ameacas": len(ameacas),
        "alertas_transmitidos": transmitidos,
        "ips_anomalos": anomalos,
        "etapas": status,
    }
    return {"resumo": resumo, "eventos": eventos, "alertas": nucleo["alertas"], "ameacas": ameacas}
