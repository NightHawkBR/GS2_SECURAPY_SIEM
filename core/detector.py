"""Módulo 3 — Detector: brute force, port scan e blacklist (dict + set), consolidados em ameaças.

Bônus (2º sem): correlação temporal — brute force em rajada dentro de uma janela de tempo.
"""

from datetime import datetime, timedelta

from core.regras import classificar_severidade, extrair_valor

FORMATO_TIMESTAMP = "%Y-%m-%d %H:%M:%S"
JANELA_PADRAO = 60            # segundos
LIMITE_RAJADA = 5             # falhas dentro da janela
AGRAVANTE_RAJADA = 3          # pontos a mais na ameaça: rapidez indica automação
REGRA_RAJADA = ("T001", "Brute Force em Rajada")


def _faixa(valor, faixas, padrao):
    return next((nivel for limite, nivel in faixas if valor > limite), padrao)


def detectar_brute_force(eventos, threshold=5):
    """FAILs de auth por IP. Severidade: >20 CRITICA | >10 ALTA | >5 MEDIA | >=threshold BAIXA."""
    contagem = {}
    usuarios = {}

    for evento in eventos:
        ip = evento.get("ip")
        if evento.get("fonte") != "auth" or evento.get("tipo") != "FAIL" or not ip:
            continue
        contagem[ip] = contagem.get(ip, 0) + 1
        usuario = extrair_valor(evento.get("detalhes", ""), "usuario")
        usuarios.setdefault(ip, set())
        if usuario:
            usuarios[ip].add(usuario)

    return {
        ip: {
            "tentativas": total,
            "usuarios": usuarios[ip],
            "severidade": _faixa(total, ((20, "CRITICA"), (10, "ALTA"), (5, "MEDIA")), "BAIXA"),
        }
        for ip, total in contagem.items()
        if total >= threshold
    }


def detectar_port_scan(eventos, threshold=3):
    """Portas distintas bloqueadas por IP. Severidade: >10 CRITICA | >5 ALTA | >=threshold MEDIA."""
    portas_por_ip = {}

    for evento in eventos:
        ip = evento.get("ip")
        if evento.get("fonte") != "firewall" or evento.get("tipo") != "BLOCK" or not ip:
            continue
        try:
            porta = int(extrair_valor(evento.get("detalhes", ""), "dport") or "")
        except ValueError:
            continue
        portas_por_ip.setdefault(ip, set()).add(porta)

    return {
        ip: {
            "portas": portas,
            "quantidade": len(portas),
            "severidade": _faixa(len(portas), ((10, "CRITICA"), (5, "ALTA")), "MEDIA"),
        }
        for ip, portas in portas_por_ip.items()
        if len(portas) >= threshold
    }


def verificar_blacklist(eventos, blacklist):
    """Interseção IPs dos eventos ∩ blacklist → (ips_encontrados, contagem_por_ip)."""
    encontrados = {e["ip"] for e in eventos if e.get("ip")} & set(blacklist)

    contagem = {}
    for evento in eventos:
        if evento.get("ip") in encontrados:
            contagem[evento["ip"]] = contagem.get(evento["ip"], 0) + 1
    return encontrados, contagem


def _instante(evento):
    try:
        return datetime.strptime(evento.get("timestamp", ""), FORMATO_TIMESTAMP)
    except (TypeError, ValueError):
        return None


def _maior_trecho(tentativas, janela):
    """Janela deslizante com dois ponteiros sobre tentativas ordenadas → maior trecho dentro da janela."""
    inicio, melhor = 0, (0, 0)
    for fim, (instante, _) in enumerate(tentativas):
        while instante - tentativas[inicio][0] > janela:
            inicio += 1
        if fim - inicio > melhor[1] - melhor[0]:
            melhor = (inicio, fim)
    return tentativas[melhor[0]:melhor[1] + 1]


def detectar_brute_force_temporal(eventos, janela_segundos=JANELA_PADRAO, limite=LIMITE_RAJADA):
    """FAILs do mesmo IP concentrados em uma janela de tempo (não só a contagem total).

    11 falhas em 40 s é ataque automatizado; as mesmas 11 espalhadas pelo dia, não necessariamente.
    Severidade pelo pico na janela: >=20 CRITICA | >=10 ALTA | >=limite MEDIA.
    """
    falhas = {}
    for evento in eventos:
        ip = evento.get("ip")
        if evento.get("fonte") != "auth" or evento.get("tipo") != "FAIL" or not ip:
            continue
        if (instante := _instante(evento)) is not None:
            usuario = extrair_valor(evento.get("detalhes", ""), "usuario")
            falhas.setdefault(ip, []).append((instante, usuario))

    janela = timedelta(seconds=janela_segundos)
    rajadas = {}
    for ip, tentativas in falhas.items():
        trecho = _maior_trecho(sorted(tentativas), janela)
        if len(trecho) < limite:
            continue
        inicio, fim = trecho[0][0], trecho[-1][0]
        rajadas[ip] = {
            "pico": len(trecho),
            "inicio": inicio.strftime(FORMATO_TIMESTAMP),
            "fim": fim.strftime(FORMATO_TIMESTAMP),
            "duracao_segundos": int((fim - inicio).total_seconds()),
            "janela_segundos": janela_segundos,
            "usuarios": {usuario for _, usuario in trecho if usuario},
            "severidade": _faixa(len(trecho), ((19, "CRITICA"), (9, "ALTA")), "MEDIA"),
        }
    return rajadas


def gerar_alertas_rajada(rajadas):
    """Cada rajada vira um alerta no formato do contrato — vai para o banco e para os consoles TCP."""
    regra_id, regra_nome = REGRA_RAJADA
    return [
        {
            "timestamp": rajada["fim"],
            "regra_id": regra_id,
            "regra_nome": regra_nome,
            "severidade": rajada["severidade"],
            "ip": ip,
            "descricao": (f"{rajada['pico']} falhas de login em {rajada['duracao_segundos']}s "
                          f"(janela de {rajada['janela_segundos']}s)"),
        }
        for ip, rajada in sorted(rajadas.items(), key=lambda item: item[1]["fim"])
    ]


def gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado, rajadas=None):
    """Consolida as detecções numa lista de ameaças, da mais grave para a menos grave."""
    blacklist_ips, blacklist_contagem = blacklist_resultado
    rajadas = rajadas or {}
    ameacas = []

    for ip in set(brute_force) | set(port_scan) | set(blacklist_ips) | set(rajadas):
        deteccoes, pontuacao, detalhes = [], 0, {}

        if ip in brute_force:
            deteccoes.append("brute_force")
            pontuacao += 5 + brute_force[ip]["tentativas"]
            detalhes["brute_force"] = brute_force[ip]

        if ip in port_scan:
            deteccoes.append("port_scan")
            pontuacao += 5 + port_scan[ip]["quantidade"]
            detalhes["port_scan"] = port_scan[ip]

        if ip in blacklist_ips:
            deteccoes.append("blacklist")
            pontuacao += 5
            detalhes["blacklist"] = {"contagem_eventos": blacklist_contagem.get(ip, 0)}

        if ip in rajadas:
            deteccoes.append("brute_force_rajada")
            pontuacao += AGRAVANTE_RAJADA
            detalhes["brute_force_rajada"] = rajadas[ip]

        ameacas.append({
            "ip": ip,
            "deteccoes": deteccoes,
            "pontuacao": pontuacao,
            "severidade": classificar_severidade(pontuacao),
            "detalhes": detalhes,
        })

    return sorted(ameacas, key=lambda a: a["pontuacao"], reverse=True)
