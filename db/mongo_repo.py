"""Repositório MongoDB — eventos, alertas e ameaças (volume + schema flexível).

Módulo B · Aulas 2 e 7. Todo documento sai daqui sem "_id" e com "id" (str) — pronto para JSON.
Não altere os dicts recebidos: insert_many injeta "_id" neles — grave cópias.
"""

from functools import lru_cache

from pymongo import MongoClient
from pymongo.database import Database

from config import settings

EVENTOS, ALERTAS, AMEACAS = "eventos", "alertas", "ameacas"


@lru_cache(maxsize=1)
def obter_db() -> Database:
    cliente = MongoClient(settings.MONGO_URI, serverSelectionTimeoutMS=3000)
    return cliente[settings.MONGO_DB]


def _db(db):
    return db if db is not None else obter_db()   # Database não aceita "if db:"


# ── Escrita ────────────────────────────────────────────────────

def criar_indices(db=None) -> None:
    """Índices em ip e timestamp + único em "hash". Sem TTL: os logs de teste são de 2025.  [B1]"""
    raise NotImplementedError


def salvar_eventos(eventos, db=None) -> int:
    """Grava os eventos sem duplicar ao reingerir (hash SHA-256 da linha_original). Retorna nº de novos.  [B1]"""
    raise NotImplementedError


def salvar_alertas(alertas, db=None) -> int:
    """Mesma estratégia anti-duplicata (hash de timestamp + regra_id + ip). Retorna nº de novos."""
    raise NotImplementedError


def salvar_ameacas(ameacas, db=None) -> int:
    """Upsert por IP — a análise mais recente vence. Passe por core.contratos.serializavel (há sets)."""
    raise NotImplementedError


def inserir_alerta(alerta, db=None) -> str:
    """Alerta avulso vindo do POST /api/alertas. Retorna o id gerado."""
    raise NotImplementedError


# ── Leitura ────────────────────────────────────────────────────

def buscar_eventos(fonte=None, tipo=None, ip=None, desde=None, ate=None,
                   pagina=1, tamanho=20, db=None) -> list[dict]:
    """Filtro só com os parâmetros informados, mais recentes primeiro, paginado com skip/limit.  [D1]"""
    raise NotImplementedError


def buscar_alertas(severidade=None, ip=None, pagina=1, tamanho=20, db=None) -> list[dict]:
    """Severidade no formato do contrato (CRITICA, ALTA...), mais recentes primeiro.  [D1]"""
    raise NotImplementedError


def obter_alerta(id_alerta, db=None) -> dict | None:
    """None se não existir; ValueError se o id for malformado (a API responde 400)."""
    raise NotImplementedError


def obter_ameaca(ip, db=None) -> dict | None:
    raise NotImplementedError


# ── Agregações ─────────────────────────────────────────────────

def top_ips(n=5, db=None) -> list[dict]:
    """$group por ip → $sort → $limit. Formato: [{"ip": "185.220.101.1", "total": 25}, ...]  [B2]"""
    raise NotImplementedError


def contagem_por_severidade(db=None) -> dict[str, int]:
    """{"CRITICA": 1, "ALTA": 17, ...} — alimenta o dashboard."""
    raise NotImplementedError


def contagem_por_fonte(db=None) -> dict[str, int]:
    """{"auth": 23, "firewall": 17, "web": 18}"""
    raise NotImplementedError
