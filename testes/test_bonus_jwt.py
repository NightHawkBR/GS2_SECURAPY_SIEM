"""Bônus — JWT completo: emissão no login, verificação de assinatura, emissor e expiração."""

import base64
import json

import jwt
import pytest

from api.auth import EMISSOR, decodificar_token, gerar_token
from config import settings
from db import mysql_repo

pytestmark = [pytest.mark.api, pytest.mark.jwt]

OPERADOR = {"id": 1, "nome": "Ana Costa", "email": "ana@empresa.com", "nivel_acesso": 4}
ALERTA = {"ip": "45.33.32.156", "severidade": "alta", "descricao": "Criado com JWT"}
CLAIMS_DO_INVASOR = {"sub": "invasor", "nivel": 5, "iss": EMISSOR, "iat": 0, "exp": 4102444800}


@pytest.fixture
def login_ok(monkeypatch):
    def autenticar_falso(email, senha, conexao=None):
        return dict(OPERADOR) if (email, senha) == ("ana@empresa.com", "Cyber@2024") else None

    monkeypatch.setattr(mysql_repo, "autenticar", autenticar_falso)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _criar_alerta(cliente, token):
    return cliente.post("/api/alertas", json=ALERTA, headers=_bearer(token))


# ── Emissão ────────────────────────────────────────────────────

def test_token_tem_as_claims_completas(ambiente_isolado):
    claims = decodificar_token(gerar_token("ana@empresa.com", 4))
    assert claims["sub"] == "ana@empresa.com"
    assert claims["nivel"] == 4
    assert claims["iss"] == EMISSOR
    assert claims["exp"] - claims["iat"] == settings.JWT_EXPIRA_MINUTOS * 60


def test_login_emite_jwt_que_abre_as_rotas_de_escrita(cliente, login_ok):
    resposta = cliente.post("/api/token", json={"email": "ana@empresa.com", "senha": "Cyber@2024"})
    assert resposta.status_code == 200
    corpo = resposta.get_json()
    assert corpo["tipo"] == "Bearer"
    assert corpo["token"].count(".") == 2

    criado = _criar_alerta(cliente, corpo["token"])
    assert criado.status_code == 201
    alerta = cliente.get(f"/api/alertas/{criado.get_json()['id']}").get_json()
    assert alerta["criado_por"] == "ana@empresa.com"


def test_login_com_senha_errada(cliente, login_ok):
    resposta = cliente.post("/api/token", json={"email": "ana@empresa.com", "senha": "errada"})
    assert resposta.status_code == 401


# ── Verificação ────────────────────────────────────────────────

def test_token_expirado_e_recusado(cliente, monkeypatch):
    monkeypatch.setattr(settings, "JWT_EXPIRA_MINUTOS", -1)
    assert _criar_alerta(cliente, gerar_token("ana@empresa.com")).status_code == 401


def test_token_adulterado_e_recusado(cliente):
    cabecalho, carga, assinatura = gerar_token("ana@empresa.com", 1).split(".")
    claims = json.loads(base64.urlsafe_b64decode(carga + "=" * (-len(carga) % 4)))
    claims["nivel"] = 5
    forjada = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    assert _criar_alerta(cliente, f"{cabecalho}.{forjada}.{assinatura}").status_code == 401


def test_token_assinado_com_outra_chave_e_recusado(cliente):
    falso = jwt.encode(CLAIMS_DO_INVASOR, "chave-do-atacante-com-mais-de-32-bytes", algorithm="HS256")
    assert _criar_alerta(cliente, falso).status_code == 401


def test_token_sem_assinatura_alg_none_e_recusado(cliente):
    assert _criar_alerta(cliente, jwt.encode(CLAIMS_DO_INVASOR, None, algorithm="none")).status_code == 401


# ── Token de serviço (automações) ──────────────────────────────

def test_token_de_servico_continua_valendo(cliente):
    assert _criar_alerta(cliente, settings.API_TOKEN).status_code == 201


def test_sem_api_token_so_jwt_entra(cliente, monkeypatch):
    monkeypatch.setattr(settings, "API_TOKEN", None)
    assert _criar_alerta(cliente, "").status_code == 401
    assert _criar_alerta(cliente, gerar_token("ana@empresa.com", 2)).status_code == 201
