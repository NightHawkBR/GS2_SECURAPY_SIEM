"""Ingestão inicial: lê os logs pelo núcleo e popula o MongoDB."""

import logging
import sys

from pymongo.errors import PyMongoError

from config import settings
from core.coletor import carregar_todos_os_logs
from core.enriquecimento import carregar_cache
from db import mongo_repo

log = logging.getLogger("securapy.migracao")

def migrar(pasta_logs=settings.PASTA_LOGS, db=None) -> int:
    """Cria os índices e grava os eventos da pasta. Retorna quantos foram inseridos."""

    mongo_repo.criar_indices(db)

    eventos = carregar_todos_os_logs(pasta_logs)
    if not eventos:
        return 0

    inseridos = mongo_repo.salvar_eventos(eventos, db)
    return inseridos

def semear_geolocalizacao(caminho=settings.ARQUIVO_CACHE_GEO, db=None) -> int:
    """Leva a geolocalização conhecida do 1º semestre (JSON) para a coleção do MongoDB."""
    perfis = [p for ip, p in carregar_cache(caminho).items() if isinstance(p, dict) and p.get("ip") == ip]
    return mongo_repo.inserir_geolocalizacoes(perfis, db)

def preparar_banco(db=None) -> None:
    """Na subida da API: índices + carga inicial da geolocalização. Banco fora do ar só gera aviso."""
    try:
        mongo_repo.criar_indices(db)
        semear_geolocalizacao(db=db)
    except PyMongoError as erro:
        log.warning("MongoDB indisponível na subida: %s", type(erro).__name__)

if __name__ == "__main__":
    pasta = sys.argv[1] if len(sys.argv) > 1 else settings.PASTA_LOGS
    print(f"[OK] {migrar(pasta)} eventos persistidos no MongoDB.")
    print(f"[OK] {semear_geolocalizacao()} geolocalizações iniciais gravadas.")
