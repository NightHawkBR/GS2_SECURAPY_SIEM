"""Módulo 1 — Coletor: lê os logs (auth, firewall, web) e normaliza em eventos (ver core.contratos.Evento)."""

import os


def _evento(partes, fonte, ip, detalhes, linha):
    return {
        "timestamp": f"{partes[0]} {partes[1]}",
        "fonte": fonte,
        "tipo": partes[2],
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha,
    }


def parsear_linha_auth(linha):
    """'2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1' → evento ou None."""
    if not linha:
        return None
    partes = linha.split()
    if len(partes) < 5:
        return None

    ip = detalhes = None
    for parte in partes[3:]:
        if parte.startswith("ip="):
            ip = parte[3:]
        elif parte.startswith("usuario="):
            detalhes = parte

    if ip is None or detalhes is None:
        return None
    return _evento(partes, "auth", ip, detalhes, linha)


def parsear_linha_firewall(linha):
    """'... BLOCK proto=TCP src=1.2.3.4 dst=10.0.0.1 dport=22' → evento (ip = src) ou None."""
    if not linha:
        return None
    partes = linha.split()
    if len(partes) < 6:
        return None

    ip = None
    detalhes = []
    for parte in partes[3:]:
        if parte.startswith("src="):
            ip = parte[4:]
        else:
            detalhes.append(parte)

    if ip is None:
        return None
    return _evento(partes, "firewall", ip, " ".join(detalhes), linha)


def parsear_linha_web(linha):
    """'... GET url=/index.html ip=1.2.3.4 status=200' → evento ou None."""
    if not linha or not all(campo in linha for campo in ("url=", "ip=", "status=")):
        return None
    partes = linha.split()
    if len(partes) < 3:
        return None

    # busca a partir do fim: a URL pode conter espaços e caracteres especiais
    pos_ip = linha.rfind(" ip=")
    pos_status = linha.rfind(" status=")
    pos_url = linha.find(" url=")
    if -1 in (pos_ip, pos_status, pos_url):
        return None

    ip = linha[pos_ip + 4:].split()[0]
    status = linha[pos_status + 1:].split()[0]
    url = linha[pos_url + 1:pos_ip]
    return _evento(partes, "web", ip, f"{url} {status}", linha)


PARSERS = {
    "auth": parsear_linha_auth,
    "firewall": parsear_linha_firewall,
    "web": parsear_linha_web,
}


def carregar_log(caminho_arquivo, fonte):
    """Lê um arquivo de log. Linhas inválidas são avisadas e puladas; arquivo ausente → []."""
    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as f:
            linhas = f.readlines()
    except FileNotFoundError:
        print(f"[ERRO] Arquivo nao encontrado: {caminho_arquivo}")
        return []

    parser = PARSERS.get(fonte)
    eventos = []
    for linha in linhas:
        linha = linha.strip()
        if not linha:
            continue
        evento = parser(linha) if parser else None
        if evento is None:
            print(f"[AVISO] Linha ignorada: {linha}")
        else:
            eventos.append(evento)
    return eventos


def identificar_fonte(nome_arquivo):
    """'auth.log' → 'auth' | 'firewall.log' → 'firewall' | 'web_access.log' → 'web'."""
    return next((fonte for fonte in PARSERS if fonte in nome_arquivo), None)


def carregar_todos_os_logs(pasta_logs):
    """Lê todos os .log da pasta e devolve a lista unificada de eventos."""
    try:
        arquivos = sorted(os.listdir(pasta_logs))
    except OSError:
        print(f"[ERRO] Pasta nao encontrada: {pasta_logs}")
        return []

    todos = []
    for arquivo in arquivos:
        fonte = identificar_fonte(arquivo)
        if not arquivo.endswith(".log") or fonte is None:
            continue
        eventos = carregar_log(os.path.join(pasta_logs, arquivo), fonte)
        print(f"[INFO] {arquivo}: {len(eventos)} eventos carregados")
        todos.extend(eventos)
    return todos
