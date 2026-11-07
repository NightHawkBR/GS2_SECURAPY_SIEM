"""Módulo 6 — Relatórios: filtros, ranking, exportação JSON e visões de terminal (menu clássico)."""

import json
import os
from collections import Counter
from datetime import datetime

from core.contratos import SEVERIDADES, serializavel

OPCOES_MENU = (
    "Carregar e processar logs", "Resumo geral", "Filtrar eventos", "Buscar IP",
    "Top 10 IPs suspeitos", "Ver alertas por severidade", "Enriquecer IPs suspeitos",
    "Exportar relatorio JSON", "Iniciar servidor de alertas",
)


def exibir_menu():
    print("\n╔══════════════════════════════════════════╗")
    print("║         SecuraPy SIEM — Menu             ║")
    print("╠══════════════════════════════════════════╣")
    for numero, texto in enumerate(OPCOES_MENU, start=1):
        print(f"║  {numero}. {texto:<37}║")
    print(f"║  0. {'Sair':<37}║")
    print("╚══════════════════════════════════════════╝")

    try:
        opcao = int(input("\nEscolha uma opcao: "))
        if 0 <= opcao <= len(OPCOES_MENU):
            return opcao
    except ValueError:
        pass
    print("Opcao invalida. Digite um numero entre 0 e 9.")
    return -1


def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    filtros = {"fonte": fonte, "tipo": tipo, "ip": ip}
    ativos = {campo: valor for campo, valor in filtros.items() if valor is not None}
    return [e for e in eventos if all(e.get(campo) == valor for campo, valor in ativos.items())]


def top_ips(eventos, n=10):
    return Counter(e["ip"] for e in eventos).most_common(n) if eventos else []


def _tabela_contagem(titulo, contagem, ordem):
    print(f"\n{titulo}")
    print(f"  {'Item':<12} {'Quantidade':>10}")
    print(f"  {'-' * 24}")
    for chave in ordem:
        if chave in contagem:
            print(f"  {chave:<12} {contagem[chave]:>10}")
    print(f"  {'-' * 24}")
    print(f"  {'TOTAL':<12} {sum(contagem.values()):>10}")


def resumo_geral(eventos, alertas):
    if not eventos:
        print("\n[!] Nenhum evento carregado. Use a opcao 1 primeiro.")
        return

    print("\n" + "=" * 44)
    print("           RESUMO GERAL DO SISTEMA")
    print("=" * 44)
    por_fonte = Counter(e["fonte"] for e in eventos)
    _tabela_contagem("EVENTOS POR FONTE", por_fonte, sorted(por_fonte))

    if alertas:
        _tabela_contagem("ALERTAS POR SEVERIDADE", Counter(a["severidade"] for a in alertas), SEVERIDADES)
    else:
        print("\nALERTAS POR SEVERIDADE\n  Nenhum alerta gerado.")
    print("=" * 44)


def exibir_tabela(dados, colunas):
    if not dados:
        print("  Nenhum dado para exibir.")
        return

    larguras = {c: max(len(c), *(len(str(linha.get(c, ""))) for linha in dados)) for c in colunas}
    print("  " + "  ".join(f"{c:<{larguras[c]}}" for c in colunas))
    print("  " + "  ".join("-" * larguras[c] for c in colunas))
    for linha in dados:
        print("  " + "  ".join(f"{str(linha.get(c, '')):<{larguras[c]}}" for c in colunas))


def buscar_ip(ip, eventos, alertas, cache_enriquecimento):
    if not eventos:
        print("\n[!] Nenhum evento carregado. Use a opcao 1 primeiro.")
        return

    eventos_ip = filtrar_eventos(eventos, ip=ip)
    alertas_ip = [a for a in alertas if a.get("ip") == ip]

    print("\n" + "=" * 50)
    print(f"  RELATORIO DO IP: {ip}")
    print("=" * 50)
    if eventos_ip:
        print(f"\n  Total de eventos: {len(eventos_ip)}")
        exibir_tabela(eventos_ip, ["timestamp", "fonte", "tipo", "detalhes"])
    else:
        print(f"\n  Nenhum evento encontrado para o IP {ip}.")

    print(f"\n  Alertas gerados: {len(alertas_ip)}")
    for alerta in alertas_ip:
        print(f"  [{alerta['severidade']}] {alerta['timestamp']} — {alerta['descricao']}")

    geo = cache_enriquecimento.get(ip)
    if geo:
        print("\n  GEOLOCALIZACAO:")
        for campo in ("pais", "regiao", "cidade", "org", "hostname"):
            print(f"    {campo.capitalize():<8}: {geo.get(campo, 'N/A')}")
    else:
        print("\n  Sem dados de geolocalizacao. Use a opcao 7 para enriquecer IPs.")
    print("=" * 50)


def exibir_top_ips(eventos, alertas):
    if not eventos:
        print("\n[!] Nenhum evento carregado. Use a opcao 1 primeiro.")
        return

    suspeitos = {a.get("ip") for a in alertas}
    print("\n" + "=" * 44)
    print("         TOP 10 IPs MAIS ATIVOS")
    print("=" * 44)
    print(f"  {'#':<4} {'IP':<20} {'Eventos':>7}  Status")
    print(f"  {'-' * 40}")
    for posicao, (ip, total) in enumerate(top_ips(eventos, n=10), start=1):
        status = "⚠ SUSPEITO" if ip in suspeitos else "OK"
        print(f"  {posicao:<4} {ip:<20} {total:>7}  {status}")
    print("=" * 44)


def exibir_alertas_por_severidade(alertas):
    if not alertas:
        print("\n[!] Nenhum alerta disponivel. Carregue e processe os logs primeiro.")
        return

    for severidade in SEVERIDADES:
        grupo = [a for a in alertas if a.get("severidade", "INFO") == severidade]
        if not grupo:
            continue
        print(f"\n  [{severidade}] — {len(grupo)} alerta(s)")
        print(f"  {'-' * 48}")
        for a in grupo:
            print(f"  {a.get('timestamp', '??')}  IP: {a.get('ip', '??'):<18}  {a.get('descricao', '??')}")


def montar_dados_relatorio(eventos, alertas, cache_enriquecimento, ameacas=None):
    return {
        "gerado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "resumo": {
            "total_eventos": len(eventos),
            "total_alertas": len(alertas),
            "eventos_por_fonte": dict(Counter(e["fonte"] for e in eventos)),
            "alertas_por_severidade": dict(Counter(a["severidade"] for a in alertas)),
        },
        "top_ips": [{"ip": ip, "eventos": total} for ip, total in top_ips(eventos, n=10)],
        "ameacas": serializavel(ameacas or []),
        "alertas": alertas,
        "enriquecimento": cache_enriquecimento,
    }


def exportar_relatorio_json(dados, caminho):
    try:
        if pasta := os.path.dirname(caminho):
            os.makedirs(pasta, exist_ok=True)
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(serializavel(dados), f, indent=2, ensure_ascii=False, default=str)
        print(f"\n[✓] Relatorio exportado com sucesso: {caminho}")
    except OSError as erro:
        print(f"\n[ERRO] Nao foi possivel salvar o relatorio: {erro}")


def gerar_nome_relatorio(pasta="saida"):
    return os.path.join(pasta, f"relatorio_{datetime.now():%Y%m%d_%H%M%S}.json")
