"""Repositório MongoDB — eventos, alertas, ameaças e geolocalização (volume + schema flexível)."""

import hashlib
import logging
from datetime import datetime, timezone
from functools import lru_cache
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.database import Database
from pymongo.errors import BulkWriteError, PyMongoError
from bson.objectid import ObjectId
from bson.errors import InvalidId

from core.contratos import serializavel
from config import settings

EVENTOS, ALERTAS, AMEACAS, GEOLOCALIZACAO = "eventos", "alertas", "ameacas", "geolocalizacao"
VALIDADE_GEO_SEGUNDOS = 30 * 24 * 3600      # TTL: o próprio MongoDB expira a geolocalização antiga
ORDENACOES_ALERTA = {
    "data": [("timestamp", DESCENDING)],
    "risco": [("score", DESCENDING), ("timestamp", DESCENDING)],
}

log = logging.getLogger("securapy.mongo")

@lru_cache(maxsize=1)
def obter_db() -> Database:
    cliente = MongoClient(settings.MONGO_URI, serverSelectionTimeoutMS=3000)
    return cliente[settings.MONGO_DB]

def _db(db):
    return db if db is not None else obter_db()

def _formatar_saida(doc: dict) -> dict | None:
    """Converte ObjectId para str, mantendo o padrão JSON (Exigência da arquitetura)."""
    if not doc: return None
    doc["id"] = str(doc.pop("_id"))
    return doc

# ── Escrita ────────────────────────────────────────────────────

def criar_indices(db=None) -> None:
    """Índices em ip e timestamp + único em "hash". Geolocalização: único em ip + TTL."""
    banco = _db(db)
    banco[EVENTOS].create_index([("ip", ASCENDING)])
    banco[EVENTOS].create_index([("timestamp", DESCENDING)])
    banco[EVENTOS].create_index([("hash", ASCENDING)], unique=True)

    banco[ALERTAS].create_index([("ip", ASCENDING)])
    banco[ALERTAS].create_index([("severidade", DESCENDING)])
    banco[ALERTAS].create_index([("score", DESCENDING), ("timestamp", DESCENDING)])
    banco[ALERTAS].create_index([("hash", ASCENDING)], unique=True)

    banco[GEOLOCALIZACAO].create_index([("ip", ASCENDING)], unique=True)
    banco[GEOLOCALIZACAO].create_index([("consultado_em", ASCENDING)], expireAfterSeconds=VALIDADE_GEO_SEGUNDOS)

def salvar_eventos(eventos, db=None) -> int:
    if not eventos: return 0
    banco = _db(db)
    docs = []
    for evento in eventos:
        doc = dict(evento)
        hash_string = hashlib.sha256(doc.get("linha_original", "").encode()).hexdigest()
        doc["hash"] = hash_string
        docs.append(doc)
    try:
        res = banco[EVENTOS].insert_many(docs, ordered=False)
        return len(res.inserted_ids)
    except BulkWriteError as e:
        return e.details['nInserted']

def salvar_alertas(alertas, db=None) -> int:
    """Estratégia anti-duplicata (hash de timestamp + regra_id + ip)."""
    if not alertas: return 0
    banco = _db(db)
    docs = []
    for alerta in alertas:
        doc = dict(alerta)
        conteudo = f"{doc.get('timestamp','')}{doc.get('regra_id','')}{doc.get('ip','')}"
        doc["hash"] = hashlib.sha256(conteudo.encode()).hexdigest()
        docs.append(doc)
    try:
        res = banco[ALERTAS].insert_many(docs, ordered=False)
        return len(res.inserted_ids)
    except BulkWriteError as e:
        return e.details['nInserted']

def atualizar_prioridade(prioridades, db=None) -> None:
    """{ip: {"score", "rotulo_ml", "anomalia"}} em TODOS os alertas do IP, inclusive os de análises anteriores."""
    banco = _db(db)
    for ip, campos in prioridades.items():
        banco[ALERTAS].update_many({"ip": ip}, {"$set": campos})

def salvar_ameacas(ameacas, db=None) -> int:
    if not ameacas: return 0
    banco = _db(db)
    inseridos = 0
    for ameaca in ameacas:
        doc_limpo = serializavel(dict(ameaca))
        ip = doc_limpo["ip"]
        res = banco[AMEACAS].update_one({"ip": ip}, {"$set": doc_limpo}, upsert=True)
        if res.upserted_id or res.modified_count: inseridos += 1
    return inseridos

def inserir_alerta(alerta, db=None) -> str:
    """Alerta avulso vindo do POST /api/alertas. Retorna o id gerado."""
    banco = _db(db)
    doc = dict(alerta)
    res = banco[ALERTAS].insert_one(doc)
    return str(res.inserted_id)

# ── Leitura ────────────────────────────────────────────────────

def buscar_eventos(fonte=None, tipo=None, ip=None, desde=None, ate=None,
                   pagina=1, tamanho=20, db=None) -> list[dict]:
    banco = _db(db)
    filtro = {}
    if fonte: filtro["fonte"] = fonte
    if tipo: filtro["tipo"] = tipo
    if ip: filtro["ip"] = ip
    if desde or ate:
        filtro["timestamp"] = {}
        if desde: filtro["timestamp"]["$gte"] = desde
        if ate: filtro["timestamp"]["$lte"] = ate

    cursor = banco[EVENTOS].find(filtro).sort("timestamp", DESCENDING)
    cursor = cursor.skip((pagina - 1) * tamanho).limit(tamanho)
    return [_formatar_saida(doc) for doc in cursor]

def buscar_alertas(severidade=None, ip=None, pagina=1, tamanho=20, ordenar="data", db=None) -> list[dict]:
    """ordenar="data" (mais recentes primeiro) ou "risco" (score do ML do IP, depois data).  [C3]"""
    banco = _db(db)
    filtro = {}
    if severidade: filtro["severidade"] = severidade
    if ip: filtro["ip"] = ip

    cursor = banco[ALERTAS].find(filtro).sort(ORDENACOES_ALERTA[ordenar])
    cursor = cursor.skip((pagina - 1) * tamanho).limit(tamanho)
    return [_formatar_saida(doc) for doc in cursor]

def obter_alerta(id_alerta, db=None) -> dict | None:
    banco = _db(db)
    try:
        obj_id = ObjectId(id_alerta)
    except InvalidId:
        raise ValueError(f"ID {id_alerta} malformado.")
    doc = banco[ALERTAS].find_one({"_id": obj_id})
    return _formatar_saida(doc)

def obter_ameaca(ip, db=None) -> dict | None:
    banco = _db(db)
    doc = banco[AMEACAS].find_one({"ip": ip})
    return _formatar_saida(doc)

def listar_ameacas(n=50, db=None) -> list[dict]:
    """Ameaças da mais arriscada para a menos: score do ML, depois a pontuação das regras.  [C3]"""
    banco = _db(db)
    cursor = banco[AMEACAS].find().sort([("score", DESCENDING), ("pontuacao", DESCENDING)]).limit(n)
    return [_formatar_saida(doc) for doc in cursor]

# ── Agregações ─────────────────────────────────────────────────

def top_ips(n=5, db=None) -> list[dict]:
    banco = _db(db)
    pipeline = [
        {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
        {"$sort": {"total": -1}},
        {"$limit": n}
    ]
    return [{"ip": doc["_id"], "total": doc["total"]} for doc in banco[EVENTOS].aggregate(pipeline)]

def ips_por_risco(n=10, db=None) -> list[dict]:
    """IPs com alerta, do maior score do ML para o menor — o "top IPs suspeitos" do painel.  [C3][E1]"""
    banco = _db(db)
    pipeline = [
        {"$match": {"ip": {"$ne": None}}},
        {"$group": {"_id": "$ip", "score": {"$max": "$score"}, "anomalia": {"$max": "$anomalia"},
                    "alertas": {"$sum": 1}}},
        {"$sort": {"score": -1, "alertas": -1, "_id": 1}},
        {"$limit": n},
    ]
    return [{"ip": doc["_id"], "score": doc["score"], "anomalia": bool(doc["anomalia"]), "alertas": doc["alertas"]}
            for doc in banco[ALERTAS].aggregate(pipeline)]

def contagem_por_severidade(db=None) -> dict[str, int]:
    banco = _db(db)
    pipeline = [{"$group": {"_id": "$severidade", "total": {"$sum": 1}}}]
    return {doc["_id"]: doc["total"] for doc in banco[ALERTAS].aggregate(pipeline) if doc["_id"]}

def contagem_por_fonte(db=None) -> dict[str, int]:
    banco = _db(db)
    pipeline = [{"$group": {"_id": "$fonte", "total": {"$sum": 1}}}]
    return {doc["_id"]: doc["total"] for doc in banco[EVENTOS].aggregate(pipeline) if doc["_id"]}

# ── Geolocalização (substitui o cache em arquivo do 1º semestre) ──

def _agora():
    return datetime.now(timezone.utc)

def buscar_geolocalizacao(ip, db=None) -> dict | None:
    banco = _db(db)
    return banco[GEOLOCALIZACAO].find_one({"ip": ip}, {"_id": 0, "consultado_em": 0})

def salvar_geolocalizacao(perfil, db=None) -> None:
    """Upsert por ip: consulta nova sobrescreve a antiga e renova o prazo do TTL."""
    banco = _db(db)
    banco[GEOLOCALIZACAO].update_one(
        {"ip": perfil["ip"]}, {"$set": {**perfil, "consultado_em": _agora()}}, upsert=True
    )

def inserir_geolocalizacoes(perfis, db=None) -> int:
    """Carga inicial: grava só os IPs que ainda não estão no banco (nunca sobrescreve)."""
    banco = _db(db)
    inseridos = 0
    for perfil in perfis:
        res = banco[GEOLOCALIZACAO].update_one(
            {"ip": perfil["ip"]}, {"$setOnInsert": {**perfil, "consultado_em": _agora()}}, upsert=True
        )
        inseridos += res.upserted_id is not None
    return inseridos

class CacheGeolocalizacao:
    """Coleção "geolocalizacao" com cara de dict: o core.enriquecimento.consultar_ip não muda.

    Banco fora do ar → segue só em memória, sem travar a consulta nem repetir a espera.
    """

    def __init__(self, db=None):
        self.banco = db
        self.memoria = {}
        self.disponivel = True

    def __contains__(self, ip):
        if ip not in self.memoria and (perfil := self._tentar(buscar_geolocalizacao, ip)):
            self.memoria[ip] = perfil
        return ip in self.memoria

    def __getitem__(self, ip):
        return self.memoria[ip]

    def __setitem__(self, ip, perfil):
        self.memoria[ip] = perfil
        self._tentar(salvar_geolocalizacao, perfil)

    def _tentar(self, operacao, valor):
        if not self.disponivel:
            return None
        try:
            return operacao(valor, db=self.banco)
        except PyMongoError as erro:
            self.disponivel = False
            log.warning("geolocalização sem MongoDB: %s", type(erro).__name__)
            return None
