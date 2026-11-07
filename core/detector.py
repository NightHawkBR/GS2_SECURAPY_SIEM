"""Módulo 3 — Detector: brute force, port scan e blacklist (dict + set), consolidados em ameaças."""

from core.regras import classificar_severidade, extrair_valor


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


def gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado):
    """Consolida as 3 detecções numa lista de ameaças, da mais grave para a menos grave."""
    blacklist_ips, blacklist_contagem = blacklist_resultado
    ameacas = []

    for ip in set(brute_force) | set(port_scan) | set(blacklist_ips):
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

        ameacas.append({
            "ip": ip,
            "deteccoes": deteccoes,
            "pontuacao": pontuacao,
            "severidade": classificar_severidade(pontuacao),
            "detalhes": detalhes,
        })

    return sorted(ameacas, key=lambda a: a["pontuacao"], reverse=True)
