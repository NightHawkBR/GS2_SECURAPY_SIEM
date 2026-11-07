"""Ingestão inicial: lê os logs pelo núcleo e popula o MongoDB. Módulo B · requisito 3"""

import sys
from config import settings
from core.coletor import carregar_todos_os_logs
from db import mongo_repo

def migrar(pasta_logs=settings.PASTA_LOGS, db=None) -> int:
    """Cria os índices e grava os eventos da pasta. Retorna quantos foram inseridos. [B1]"""
    # 1. Prepara a fundação do banco
    mongo_repo.criar_indices(db)
    
    # 2. Extrai os dados utilizando o Núcleo (Módulo A)
    eventos = carregar_todos_os_logs(pasta_logs)
    if not eventos:
        return 0
        
    # 3. Salva no MongoDB usando a nossa estratégia Anti-Duplicata
    inseridos = mongo_repo.salvar_eventos(eventos, db)
    return inseridos

if __name__ == "__main__":
    pasta = sys.argv[1] if len(sys.argv) > 1 else settings.PASTA_LOGS
    print(f"[OK] {migrar(pasta)} eventos persistidos no MongoDB.")