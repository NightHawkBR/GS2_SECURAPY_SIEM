"""Módulo 2 — Motor de regras: carrega config/regras.json e gera alertas (ver core.contratos.Alerta)."""

import json

FAIXAS_SEVERIDADE = ((9, "CRITICA"), (7, "ALTA"), (5, "MEDIA"), (3, "BAIXA"))


def carregar_regras(caminho_config):
    """Lê o JSON e devolve só as regras ativas. Arquivo ausente ou inválido → []."""
    try:
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo de regras nao encontrado: {caminho_config}")
        return []
    except json.JSONDecodeError:
        print(f"[ERRO] JSON invalido em: {caminho_config}")
        return []

    return [regra for regra in dados.get("regras", []) if regra.get("ativa", False)]


def classificar_severidade(pontuacao):
    """>=9 CRITICA | >=7 ALTA | >=5 MEDIA | >=3 BAIXA | <3 INFO."""
    return next((nivel for minimo, nivel in FAIXAS_SEVERIDADE if pontuacao >= minimo), "INFO")


def extrair_valor(detalhes, chave):
    """extrair_valor('proto=TCP dport=22', 'dport') → '22' (None se ausente)."""
    for parte in detalhes.split():
        if parte.startswith(f"{chave}="):
            return parte.split("=", 1)[1]
    return None


def _porta_critica(regra, evento):
    if evento.get("tipo") != "BLOCK":
        return False
    try:
        porta = int(extrair_valor(evento.get("detalhes", ""), "dport") or "")
    except ValueError:
        return False
    return porta in regra.get("portas_criticas", [])


def _contem(url, padroes):
    return any(padrao in url for padrao in padroes)


def _disparou(regra, evento):
    detalhes = evento.get("detalhes", "")
    url = extrair_valor(detalhes, "url") or ""

    match regra.get("condicao"):
        case "usuario_privilegiado":
            return extrair_valor(detalhes, "usuario") in regra.get("usuarios_alvo", [])
        case "porta_critica":
            return _porta_critica(regra, evento)
        case "path_traversal" | "xss":
            return _contem(url, regra.get("padroes", []))
        case "reconhecimento":
            return _contem(url, regra.get("urls_suspeitas", []))
    return False


def avaliar_regra(regra, evento):
    """Devolve o alerta se o evento viola a regra; senão None."""
    if evento.get("fonte") != regra.get("fonte") or not _disparou(regra, evento):
        return None

    return {
        "timestamp": evento.get("timestamp"),
        "regra_id": regra.get("id"),
        "regra_nome": regra.get("nome"),
        "severidade": classificar_severidade(regra.get("severidade_base", 0)),
        "ip": evento.get("ip"),
        "descricao": regra.get("descricao", ""),
    }


def aplicar_regras(eventos, regras):
    """Testa cada evento contra todas as regras. Um evento pode gerar vários alertas."""
    return [
        alerta
        for evento in eventos
        for regra in regras
        if (alerta := avaliar_regra(regra, evento)) is not None
    ]
