"""Núcleo em uma chamada: eventos → regras → detector. Não conhece banco, ML nem web."""

from core.coletor import carregar_todos_os_logs
from core.detector import (
    detectar_brute_force,
    detectar_port_scan,
    gerar_resumo_ameacas,
    verificar_blacklist,
)
from core.regras import aplicar_regras, carregar_regras


def analisar_eventos(eventos, regras, blacklist):
    """Devolve {'eventos', 'alertas', 'ameacas'} — mesmo fluxo da opção 1 do menu do 1º sem."""
    ameacas = gerar_resumo_ameacas(
        detectar_brute_force(eventos),
        detectar_port_scan(eventos),
        verificar_blacklist(eventos, blacklist),
    )
    return {"eventos": eventos, "alertas": aplicar_regras(eventos, regras), "ameacas": ameacas}


def analisar_pasta(pasta_logs, caminho_regras, blacklist):
    return analisar_eventos(carregar_todos_os_logs(str(pasta_logs)), carregar_regras(caminho_regras), blacklist)
