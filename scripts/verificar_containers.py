"""Confere, via Docker SDK, se os 3 serviços do compose estão "running".  Módulo F · Aula 11

Uso: python scripts/verificar_containers.py   (código de saída 0 = tudo no ar)
"""

import sys

import docker

PROJETO = "securapy"
SERVICOS = ("api", "mongodb", "mysql")
LABEL_PROJETO = "com.docker.compose.project"
LABEL_SERVICO = "com.docker.compose.service"
STATUS_RODANDO = "running"


def status_plataforma(cliente=None):
    if cliente is None:
        cliente = docker.from_env()
    conteineres = cliente.containers.list(all=True, filters={"label": f"{LABEL_PROJETO}={PROJETO}"})

    por_servico = {}
    for conteiner in conteineres:
        rotulos = conteiner.labels or {}
        servico = rotulos.get(LABEL_SERVICO)
        if rotulos.get(LABEL_PROJETO) == PROJETO and servico in SERVICOS:
            por_servico.setdefault(servico, []).append(conteiner)

    status = []
    for servico in SERVICOS:
        encontrados = por_servico.get(servico)
        if not encontrados:
            status.append({"servico": servico, "nome": "-", "status": "ausente"})
            continue
        status.extend({"servico": servico, "nome": c.name, "status": c.status} for c in encontrados)
    return status


def todos_rodando(status):
    rodando = {item["servico"] for item in status if item["status"] == STATUS_RODANDO}
    return set(SERVICOS) <= rodando


def exibir(status):
    cabecalho = {"servico": "SERVIÇO", "nome": "CONTÊINER", "status": "STATUS"}
    linhas = [cabecalho, *status]
    larguras = {campo: max(len(linha[campo]) for linha in linhas) for campo in cabecalho}

    for linha in linhas:
        texto = " | ".join(linha[campo].ljust(larguras[campo]) for campo in cabecalho)
        if linha is not cabecalho and linha["status"] != STATUS_RODANDO:
            texto += "  <- FORA DO AR"
        print(texto.rstrip())

    rodando = sum(1 for item in status if item["status"] == STATUS_RODANDO)
    print(f"Total: {len(status)} | Rodando: {rodando} | Fora do ar: {len(status) - rodando}")


if __name__ == "__main__":
    try:
        status = status_plataforma()
    except docker.errors.DockerException:
        print("[ERRO] Docker indisponível — o Docker Desktop está aberto?")
        sys.exit(2)
    exibir(status)
    sys.exit(0 if todos_rodando(status) else 1)
