"""Repositório MongoDB — eventos, alertas e ameaças (volume + schema flexível)."""

import hashlib
from functools import lru_cache
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.database import Database
from pymongo.errors import BulkWriteError
from bson.objectid import ObjectId
from bson.errors import InvalidId

from core.contratos import serializavel
from config import settings

EVENTOS, ALERTAS, AMEACAS = "eventos", "alertas", "ameacas"

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
    """Índices em ip e timestamp + único em "hash"."""
    banco = _db(db)
    banco[EVENTOS].create_index([("ip", ASCENDING)])
    banco[EVENTOS].create_index([("timestamp", DESCENDING)])
    banco[EVENTOS].create_index([("hash", ASCENDING)], unique=True)

    banco[ALERTAS].create_index([("ip", ASCENDING)])
    banco[ALERTAS].create_index([("severidade", DESCENDING)])
    banco[ALERTAS].create_index([("hash", ASCENDING)], unique=True)

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

def buscar_alertas(severidade=None, ip=None, pagina=1, tamanho=20, db=None) -> list[dict]:
    banco = _db(db)
    filtro = {}
    if severidade: filtro["severidade"] = severidade
    if ip: filtro["ip"] = ip

    cursor = banco[ALERTAS].find(filtro).sort("timestamp", DESCENDING)
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

# ── Agregações ─────────────────────────────────────────────────

def top_ips(n=5, db=None) -> list[dict]:
    banco = _db(db)
    pipeline = [
        {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
        {"$sort": {"total": -1}},
        {"$limit": n}
    ]
    return [{"ip": doc["_id"], "total": doc["total"]} for doc in banco[EVENTOS].aggregate(pipeline)]

def contagem_por_severidade(db=None) -> dict[str, int]:
    banco = _db(db)
    pipeline = [{"$group": {"_id": "$severidade", "total": {"$sum": 1}}}]
    return {doc["_id"]: doc["total"] for doc in banco[ALERTAS].aggregate(pipeline) if doc["_id"]}

def contagem_por_fonte(db=None) -> dict[str, int]:
    banco = _db(db)
    pipeline = [{"$group": {"_id": "$fonte", "total": {"$sum": 1}}}]
    return {doc["_id"]: doc["total"] for doc in banco[EVENTOS].aggregate(pipeline) if doc["_id"]}
