"""Integridade do modelo (OWASP A08): um .pkl executa código ao ser carregado — só carregue se o hash conferir.

O arquivo .sha256 segue o formato do `sha256sum` ("<hash>  modelo.pkl"), então também dá para
conferir fora do Python (Linux: sha256sum -c · PowerShell: Get-FileHash).
"""

import hashlib
import logging
from pathlib import Path

TAMANHO_BLOCO = 64 * 1024

log = logging.getLogger("securapy.ml")


class ModeloAdulteradoError(Exception):
    """SHA-256 do .pkl diferente do registrado no treino (ou hash ausente)."""


def calcular_sha256(caminho) -> str:
    """Hash hexadecimal do arquivo, lido em blocos (não carrega o arquivo inteiro na memória).  [C4]"""
    sha = hashlib.sha256()
    with open(caminho, "rb") as arquivo:
        while bloco := arquivo.read(TAMANHO_BLOCO):
            sha.update(bloco)
    return sha.hexdigest()


def registrar_hash(caminho_modelo, caminho_hash) -> str:
    valor = calcular_sha256(caminho_modelo)
    Path(caminho_hash).write_text(f"{valor}  {Path(caminho_modelo).name}\n", encoding="utf-8")
    return valor


def verificar_integridade(caminho_modelo, caminho_hash) -> None:
    """Hash divergente ou .sha256 ausente → alerta no log + ModeloAdulteradoError.  [C4]"""
    try:
        esperado = Path(caminho_hash).read_text(encoding="utf-8").split()[0]
    except (FileNotFoundError, IndexError):
        log.critical("Modelo %s sem hash registrado — carregamento bloqueado", Path(caminho_modelo).name)
        raise ModeloAdulteradoError("hash do modelo não registrado")

    if calcular_sha256(caminho_modelo) != esperado.lower():
        log.critical("ALERTA: %s foi modificado após o treino — carregamento bloqueado", Path(caminho_modelo).name)
        raise ModeloAdulteradoError("hash do modelo não confere")
