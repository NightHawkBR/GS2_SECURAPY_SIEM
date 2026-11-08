"""Núcleo em uma chamada: eventos → regras → detector. Não conhece banco, ML nem web."""

from core.coletor import carregar_todos_os_logs
from core.detector import (
    JANELA_PADRAO,
    LIMITE_RAJADA,
    detectar_brute_force,
    detectar_brute_force_temporal,
    detectar_port_scan,
    gerar_alertas_rajada,
    gerar_resumo_ameacas,
    verificar_blacklist,
)
from core.regras import aplicar_regras, carregar_regras


def analisar_eventos(eventos, regras, blacklist, janela_segundos=JANELA_PADRAO, limite_rajada=LIMITE_RAJADA):
    """Devolve {'eventos', 'alertas', 'ameacas'} — fluxo da opção 1 do menu do 1º sem + correlação temporal."""
    rajadas = detectar_brute_force_temporal(eventos, janela_segundos, limite_rajada)
    ameacas = gerar_resumo_ameacas(
        detectar_brute_force(eventos),
        detectar_port_scan(eventos),
        verificar_blacklist(eventos, blacklist),
        rajadas,
    )
    alertas = aplicar_regras(eventos, regras) + gerar_alertas_rajada(rajadas)
    return {"eventos": eventos, "alertas": alertas, "ameacas": ameacas}


def analisar_pasta(pasta_logs, caminho_regras, blacklist, **opcoes):
    eventos = carregar_todos_os_logs(str(pasta_logs))
    return analisar_eventos(eventos, carregar_regras(caminho_regras), blacklist, **opcoes)
