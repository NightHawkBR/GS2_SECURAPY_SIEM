"""Módulo 5 — Enriquecimento de IPs via ipinfo.io.

Melhorias do 2º semestre (Aula 10): cache em dict (O(1)), backoff exponencial em 429,
token opcional por variável de ambiente e IPs internos nunca saem para a internet.
"""

import ipaddress
import json
import os
import time
from pathlib import Path

import requests

API_URL = "https://ipinfo.io/{ip}/json"
TIMEOUT = 5
TENTATIVAS = 3
CAMPOS = ("cidade", "regiao", "pais", "org", "hostname")
REDES_INTERNAS = tuple(
    ipaddress.ip_network(rede)
    for rede in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)


def _perfil(ip, privado, padrao="Desconhecido", **dados):
    return {"ip": ip, "privado": privado, **{campo: dados.get(campo) or padrao for campo in CAMPOS}}


def ip_valido(ip):
    try:
        ipaddress.ip_address(str(ip))
        return True
    except ValueError:
        return False


def eh_ip_privado(ip):
    """Aceita str ou ip_address. RFC 1918 + loopback → True; inválido → False."""
    try:
        endereco = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(endereco in rede for rede in REDES_INTERNAS)


def _requisitar(ip):
    token = os.environ.get("IPINFO_TOKEN")
    cabecalhos = {"Authorization": f"Bearer {token}"} if token else {}

    for tentativa in range(TENTATIVAS):
        resposta = requests.get(API_URL.format(ip=ip), headers=cabecalhos, timeout=TIMEOUT)
        if resposta.status_code == 429:
            time.sleep(2 ** tentativa)
            continue
        return resposta.json() if resposta.status_code == 200 else None
    return None


def consultar_ip(ip, cache):
    """Geolocalização do IP usando o cache (dict ip → perfil). Falhas de rede não travam."""
    ip = str(ip)
    if ip in cache:
        return cache[ip]
    if not ip_valido(ip):
        return _perfil(ip, False, "Invalido")
    if eh_ip_privado(ip):
        cache[ip] = _perfil(ip, True, "Rede Interna")
        return cache[ip]

    try:
        dados = _requisitar(ip)
    except (requests.RequestException, ValueError) as erro:
        print(f"[AVISO] Enriquecimento indisponivel para {ip}: {type(erro).__name__}")
        return _perfil(ip, False)

    if not dados:
        return _perfil(ip, False)

    cache[ip] = _perfil(
        ip, False,
        cidade=dados.get("city"), regiao=dados.get("region"), pais=dados.get("country"),
        org=dados.get("org"), hostname=dados.get("hostname"),
    )
    return cache[ip]


def enriquecer_alertas(alertas, cache):
    """Adiciona 'geolocalizacao' a cada alerta, consultando cada IP único uma única vez."""
    ips = {alerta["ip"] for alerta in alertas if alerta.get("ip")}
    geo = {ip: consultar_ip(ip, cache) for ip in ips}

    for alerta in alertas:
        if alerta.get("ip") in geo:
            alerta["geolocalizacao"] = geo[alerta["ip"]]
    return alertas


def carregar_cache(caminho):
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            dados = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    if isinstance(dados, list):  # formato antigo (lista) do 1º semestre
        return {item["ip"]: item for item in dados if "ip" in item}
    return dados


def salvar_cache(cache, caminho):
    try:
        Path(caminho).parent.mkdir(parents=True, exist_ok=True)
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except OSError as erro:
        print(f"[AVISO] Nao foi possivel salvar o cache: {erro}")


def exibir_enriquecimento(dados_ip):
    if not dados_ip:
        print("Nenhum dado de IP disponivel para exibicao.")
        return

    tipo = "Privado (Interno)" if dados_ip.get("privado") else "Publico (Externo)"
    print("-" * 50)
    print(f"{'ANALISE DE CONTEXTO DE IP':^50}")
    print("-" * 50)
    for rotulo, valor in (("IP", dados_ip.get("ip")), ("Tipo", tipo),
                          *((campo.capitalize(), dados_ip.get(campo)) for campo in CAMPOS)):
        print(f"{rotulo + ':':<15} {valor}")
    print("-" * 50)
