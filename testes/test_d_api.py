"""Módulo D — API REST. Cenários D1–D5 da GS + tratamento de erros (GS 6.2).

Depende do Módulo B: a base é populada no mongomock pelo orquestrador (ordem B → C → D).
"""

import pytest

from api.auth import gerar_token
from db import mongo_repo

pytestmark = pytest.mark.api

ALERTA_VALIDO = {"ip": "45.33.32.156", "severidade": "alta", "descricao": "Scan manual confirmado"}
EVENTO_VALIDO = {"timestamp": "2026-11-08 10:00:00", "fonte": "auth", "tipo": "FAIL", "ip": "203.0.113.5",
                 "detalhes": "usuario=root", "linha_original": "2026-11-08 10:00:00 FAIL usuario=root ip=203.0.113.5"}


def test_saude(cliente):
    resposta = cliente.get("/api/saude")
    assert resposta.status_code == 200
    assert resposta.get_json()["status"] == "online"


# ── D1: filtros e paginação ────────────────────────────────────

def test_d1_alertas_criticos_paginados(cliente, base_populada):
    resposta = cliente.get("/api/alertas?severidade=critica&pagina=1&tamanho=5")
    assert resposta.status_code == 200
    corpo = resposta.get_json()
    assert corpo["pagina"] == 1 and corpo["tamanho"] == 5
    assert 1 <= len(corpo["itens"]) <= 5
    assert all(alerta["severidade"] == "CRITICA" for alerta in corpo["itens"])


def test_d1_paginas_nao_se_repetem(cliente, base_populada):
    pagina1 = cliente.get("/api/alertas?pagina=1&tamanho=10").get_json()["itens"]
    pagina2 = cliente.get("/api/alertas?pagina=2&tamanho=10").get_json()["itens"]
    assert len(pagina1) == len(pagina2) == 10
    assert not {a["id"] for a in pagina1} & {a["id"] for a in pagina2}


def test_eventos_com_filtros(cliente, base_populada):
    resposta = cliente.get("/api/eventos?fonte=auth&tipo=FAIL&tamanho=100")
    assert resposta.status_code == 200
    itens = resposta.get_json()["itens"]
    assert len(itens) == 19
    assert all(e["fonte"] == "auth" and e["tipo"] == "FAIL" for e in itens)


@pytest.mark.parametrize("consulta", ["pagina=0", "pagina=abc", "tamanho=0", "tamanho=1000", "severidade=urgente"])
def test_parametros_invalidos_retornam_400(cliente, consulta):
    resposta = cliente.get(f"/api/alertas?{consulta}")
    assert resposta.status_code == 400
    assert "erro" in resposta.get_json()


# ── D2 / D5: investigação de IP ────────────────────────────────

def test_d2_investigar_ip(cliente, base_populada):
    resposta = cliente.get("/api/ip/185.220.101.1")
    assert resposta.status_code == 200
    corpo = resposta.get_json()
    assert {"ip", "eventos", "alertas", "geolocalizacao", "score"} <= corpo.keys()
    assert len(corpo["eventos"]) == 25
    assert corpo["alertas"]
    assert corpo["geolocalizacao"]["ip"] == "185.220.101.1"


@pytest.mark.parametrize("ip", ["999.1.1.1", "abc", "185.220.101", "1.2.3.4.5"])
def test_d5_ip_malformado(cliente, ip):
    resposta = cliente.get(f"/api/ip/{ip}")
    assert resposta.status_code == 400
    assert "erro" in resposta.get_json()


# ── D3 / D4: escrita autenticada ───────────────────────────────

def test_d3_post_sem_token(cliente):
    assert cliente.post("/api/alertas", json=ALERTA_VALIDO).status_code == 401


def test_d3_token_invalido(cliente):
    resposta = cliente.post("/api/alertas", json=ALERTA_VALIDO, headers={"Authorization": "Bearer falso"})
    assert resposta.status_code == 401


@pytest.mark.parametrize("corpo", [
    {},
    {"ip": "45.33.32.156"},
    {**ALERTA_VALIDO, "ip": "999.1.1.1"},
    {**ALERTA_VALIDO, "severidade": "urgente"},
    {**ALERTA_VALIDO, "descricao": 42},
])
def test_d4_corpo_invalido(cliente, cabecalho_auth, corpo):
    assert cliente.post("/api/alertas", json=corpo, headers=cabecalho_auth).status_code == 400


def test_d4_corpo_que_nao_e_json(cliente, cabecalho_auth):
    resposta = cliente.post("/api/alertas", data="nao-e-json", headers=cabecalho_auth, content_type="text/plain")
    assert resposta.status_code == 400


def test_cria_e_obtem_alerta(cliente, cabecalho_auth):
    criado = cliente.post("/api/alertas", json=ALERTA_VALIDO, headers=cabecalho_auth)
    assert criado.status_code == 201
    resposta = cliente.get(f"/api/alertas/{criado.get_json()['id']}")
    assert resposta.status_code == 200
    assert resposta.get_json()["descricao"] == ALERTA_VALIDO["descricao"]
    assert resposta.get_json()["severidade"] == "ALTA"


def test_alerta_id_malformado_e_inexistente(cliente):
    assert cliente.get("/api/alertas/nao-e-um-id").status_code == 400
    assert cliente.get(f"/api/alertas/{'0' * 24}").status_code == 404


# ── POST /api/analisar ─────────────────────────────────────────

def test_analisar_um_log(cliente, cabecalho_auth):
    resposta = cliente.post("/api/analisar", json={"caminho": "auth.log"}, headers=cabecalho_auth)
    assert resposta.status_code == 200
    assert resposta.get_json()["resumo"]["total_eventos"] == 23


@pytest.mark.parametrize("caminho", ["../config/regras.json", "/etc/passwd", "nao_existe.log"])
def test_analisar_caminho_recusado(cliente, cabecalho_auth, caminho):
    resposta = cliente.post("/api/analisar", json={"caminho": caminho}, headers=cabecalho_auth)
    assert resposta.status_code == 400


def test_analisar_exige_token(cliente):
    assert cliente.post("/api/analisar", json={"caminho": "auth.log"}).status_code == 401


# ── Erros não vazam detalhes internos ──────────────────────────

def test_404_em_json(cliente):
    resposta = cliente.get("/api/rota-que-nao-existe")
    assert resposta.status_code == 404
    assert "erro" in resposta.get_json()


def test_500_nao_vaza_segredos(app, cliente, monkeypatch):
    app.config["PROPAGATE_EXCEPTIONS"] = False

    def banco_quebrado(*args, **kwargs):
        raise RuntimeError("mongodb://admin:SenhaSecreta@mongodb:27017 SELECT * FROM usuarios")

    monkeypatch.setattr(mongo_repo, "buscar_alertas", banco_quebrado)
    resposta = cliente.get("/api/alertas")
    texto = resposta.get_data(as_text=True)
    assert resposta.status_code in (500, 503)
    assert "SenhaSecreta" not in texto and "SELECT" not in texto and "Traceback" not in texto


# ── Lote de eventos: só entra o que está no contrato ───────────

def _analisar_lote(cliente, cabecalho_auth, eventos):
    return cliente.post("/api/analisar", json={"eventos": eventos}, headers=cabecalho_auth)


@pytest.mark.parametrize("campo, valor", [
    ("ip", {"$ne": None}), ("ip", 123), ("ip", "abc"), ("fonte", "xyz"), ("tipo", "F A I L"),
    ("timestamp", "ontem"), ("detalhes", ["a"]), ("linha_original", " "), ("linha_original", None),
])
def test_lote_com_evento_incoerente_da_400(cliente, cabecalho_auth, mongo_fake, campo, valor):
    resposta = _analisar_lote(cliente, cabecalho_auth, [EVENTO_VALIDO, {**EVENTO_VALIDO, campo: valor}])
    assert resposta.status_code == 400
    assert resposta.get_json()["erro"] == "Evento 2 fora do formato esperado"
    assert mongo_fake[mongo_repo.EVENTOS].count_documents({}) == 0


def test_lote_grava_so_os_campos_do_contrato(cliente, cabecalho_auth, mongo_fake):
    resposta = _analisar_lote(cliente, cabecalho_auth, [{**EVENTO_VALIDO, "$where": "1", "extra": "x"}])
    assert resposta.status_code == 200
    assert resposta.get_json()["resumo"]["etapas"]["persistencia"] == "ok"
    gravado = mongo_fake[mongo_repo.EVENTOS].find_one({}, {"_id": 0, "hash": 0})
    assert gravado == EVENTO_VALIDO


def test_lote_grande_demais(cliente, cabecalho_auth):
    lote = [{**EVENTO_VALIDO, "linha_original": f"linha {i}"} for i in range(5001)]
    assert _analisar_lote(cliente, cabecalho_auth, lote).status_code == 400


def test_corpo_grande_demais_responde_em_json(cliente, cabecalho_auth):
    resposta = cliente.post("/api/analisar", data="x" * 3_000_000,
                            headers={**cabecalho_auth, "Content-Type": "application/json"})
    assert resposta.status_code == 413
    assert resposta.get_json() == {"erro": "Corpo da requisição grande demais"}


# ── Filtros de período e ordenação ─────────────────────────────

@pytest.mark.parametrize("consulta", [
    "desde=ontem", "ate=2025-13-01", "desde=2025-02-20 25:00:00", "desde=2025-02-21&ate=2025-02-20",
])
def test_periodo_invalido_da_400(cliente, consulta):
    assert cliente.get(f"/api/eventos?{consulta}").status_code == 400


def test_periodo_so_com_data_cobre_o_dia_inteiro(cliente, base_populada):
    no_dia = cliente.get("/api/eventos?desde=2025-02-20&ate=2025-02-20&tamanho=100").get_json()["itens"]
    depois = cliente.get("/api/eventos?desde=2025-02-21").get_json()["itens"]
    assert len(no_dia) == 58 and depois == []


def test_ordenacao_invalida_da_400(cliente):
    assert cliente.get("/api/alertas?ordenar=aleatorio").status_code == 400


# ── Nível de acesso (1–5 do MySQL, levado no JWT) ──────────────

def _bearer(nivel):
    return {"Authorization": f"Bearer {gerar_token('operador@cybershield.com', nivel)}"}


def test_nivel_1_so_consulta(cliente):
    resposta = cliente.post("/api/alertas", json=ALERTA_VALIDO, headers=_bearer(1))
    assert resposta.status_code == 403
    assert resposta.get_json() == {"erro": "Nível de acesso insuficiente"}
    assert cliente.get("/api/alertas", headers=_bearer(1)).status_code == 200


def test_nivel_2_registra_alerta_mas_nao_dispara_analise(cliente):
    assert cliente.post("/api/alertas", json=ALERTA_VALIDO, headers=_bearer(2)).status_code == 201
    assert cliente.post("/api/analisar", json={"caminho": "auth.log"}, headers=_bearer(2)).status_code == 403


def test_nivel_3_dispara_analise(cliente):
    assert cliente.post("/api/analisar", json={"caminho": "auth.log"}, headers=_bearer(3)).status_code == 200
