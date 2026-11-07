"""Módulo E — Segurança web e dashboard. Cenários E1–E4 da GS."""

import logging

import pytest

from db import mongo_repo, mysql_repo
from web.painel import CHAVE_SESSAO, MENSAGEM_LOGIN_INVALIDO

pytestmark = pytest.mark.web

OPERADOR = {"id": 1, "nome": "Ana Costa", "email": "ana@empresa.com", "nivel_acesso": 5}
PAYLOAD_XSS = "<script>alert(1)</script>"


@pytest.fixture
def operadores(monkeypatch):
    def autenticar_falso(email, senha, conexao=None):
        return dict(OPERADOR) if (email, senha) == ("ana@empresa.com", "Cyber@2024") else None

    monkeypatch.setattr(mysql_repo, "autenticar", autenticar_falso)


@pytest.fixture
def logado(cliente):
    with cliente.session_transaction() as sessao:
        sessao[CHAVE_SESSAO] = dict(OPERADOR)
    return cliente


# ── E1: XSS ────────────────────────────────────────────────────

def test_e1_xss_vira_texto_literal(logado, mongo_fake):
    mongo_repo.inserir_alerta({"timestamp": "2025-02-20 09:00:00", "regra_id": "MANUAL",
                               "regra_nome": "Teste XSS", "severidade": "ALTA",
                               "ip": "45.33.32.156", "descricao": PAYLOAD_XSS})
    resposta = logado.get("/painel")
    html = resposta.get_data(as_text=True)
    assert resposta.status_code == 200
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert PAYLOAD_XSS not in html


def test_e1_painel_mostra_os_blocos(logado, base_populada):
    html = logado.get("/painel").get_data(as_text=True)
    for trecho in ("auth", "firewall", "web", "CRITICA", "185.220.101.1"):
        assert trecho in html


def test_painel_exige_login(cliente):
    resposta = cliente.get("/painel")
    assert resposta.status_code == 302
    assert "/login" in resposta.headers["Location"]


def test_investigar_ip_no_painel(logado, base_populada):
    resposta = logado.get("/painel/ip?ip=185.220.101.1")
    assert resposta.status_code == 200
    assert "185.220.101.1" in resposta.get_data(as_text=True)


# ── E2: headers ────────────────────────────────────────────────

@pytest.mark.parametrize("rota", ["/api/saude", "/login", "/api/rota-que-nao-existe"])
def test_e2_headers_de_seguranca(cliente, rota):
    headers = cliente.get(rota).headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in headers["Content-Security-Policy"]


# ── E3: login anti-enumeração ──────────────────────────────────

def test_e3_mesma_resposta_para_senha_errada_e_usuario_inexistente(cliente, operadores):
    senha_errada = cliente.post("/login", data={"email": "ana@empresa.com", "senha": "errada"})
    inexistente = cliente.post("/login", data={"email": "ninguem@empresa.com", "senha": "errada"})
    assert senha_errada.status_code == inexistente.status_code == 401
    assert MENSAGEM_LOGIN_INVALIDO in senha_errada.get_data(as_text=True)
    assert senha_errada.get_data() == inexistente.get_data()


def test_login_valido_abre_sessao(cliente, operadores):
    resposta = cliente.post("/login", data={"email": "ana@empresa.com", "senha": "Cyber@2024"})
    assert resposta.status_code == 302
    with cliente.session_transaction() as sessao:
        assert sessao[CHAVE_SESSAO]["email"] == "ana@empresa.com"


def test_login_campos_vazios(cliente, operadores):
    assert cliente.post("/login", data={"email": "", "senha": ""}).status_code == 400


# ── E4: logging de acesso ──────────────────────────────────────

def test_e4_toda_requisicao_gera_log(cliente, caplog):
    with caplog.at_level(logging.INFO, logger="securapy.acesso"):
        cliente.get("/api/saude")
    linhas = [r.getMessage() for r in caplog.records if r.name == "securapy.acesso"]
    assert any("/api/saude" in linha and "200" in linha for linha in linhas)
