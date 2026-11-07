"""Fluxo ponta a ponta (GS §4): núcleo → ML → persistência → alertas em tempo real.

Cada etapa é isolada: módulo pendente ou serviço fora do ar vira status no resumo,
nunca derruba a análise. Usado pelo POST /api/analisar e pelo `python main.py analisar`.
"""

import logging

from alertas.servidor_alertas import broadcast_alerta
from config import settings
from core.coletor import carregar_log, carregar_todos_os_logs, identificar_fonte
from core.contratos import serializavel
from core.pipeline import analisar_eventos
from core.regras import carregar_regras
from db import mongo_repo
from ml import classificar

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


def _aplicar_scores(ameacas, classificacoes):
    por_ip = {c["ip"]: c for c in classificacoes}
    for ameaca in ameacas:
        ameaca["score"] = por_ip.get(ameaca["ip"], {}).get("score")
        ameaca["rotulo_ml"] = por_ip.get(ameaca["ip"], {}).get("rotulo")
    return sorted(ameacas, key=lambda a: (a["score"] or 0, a["pontuacao"]), reverse=True)


def _persistir(eventos, alertas, ameacas):
    mongo_repo.criar_indices()
    mongo_repo.salvar_eventos(eventos)
    mongo_repo.salvar_alertas(alertas)
    mongo_repo.salvar_ameacas(ameacas)


def _transmitir(alertas):
    urgentes = [a for a in alertas if a["severidade"] in settings.ALERTAS_TEMPO_REAL]
    for alerta in urgentes:
        broadcast_alerta(alerta)
    return len(urgentes)


def executar_analise(caminho=None, eventos=None, *, persistir=True, transmitir=True):
    """Roda a plataforma inteira. Retorna {"resumo", "eventos", "alertas", "ameacas"}."""
    eventos = carregar_eventos(caminho) if eventos is None else eventos
    nucleo = analisar_eventos(eventos, carregar_regras(settings.ARQUIVO_REGRAS), settings.BLACKLIST)
    status = {"nucleo": "ok"}

    classificacoes = _etapa(status, "ml", classificar.pontuar, eventos, padrao=[])
    ameacas = serializavel(_aplicar_scores(nucleo["ameacas"], classificacoes))

    if persistir:
        _etapa(status, "persistencia", _persistir, eventos, nucleo["alertas"], ameacas)
    transmitidos = _etapa(status, "tempo_real", _transmitir, nucleo["alertas"], padrao=0) if transmitir else 0

    resumo = {
        "total_eventos": len(eventos),
        "total_alertas": len(nucleo["alertas"]),
        "total_ameacas": len(ameacas),
        "alertas_transmitidos": transmitidos,
        "etapas": status,
    }
    return {"resumo": resumo, "eventos": eventos, "alertas": nucleo["alertas"], "ameacas": ameacas}
