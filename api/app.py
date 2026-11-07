"""API REST — porta de entrada para dashboards, automações e outros sistemas.  Módulo D · Aulas 6, 7 e 10

Produção (Docker):  gunicorn "api.app:criar_app()"
Contrato de erro:   {"erro": "<mensagem amigável>"} — nunca traceback, query ou segredo.
"""

import logging

from flask import Blueprint, Flask, jsonify, request

import orquestrador
from alertas.servidor_alertas import iniciar_em_background
from api.auth import gerar_token, token_obrigatorio
from config import settings
from core import enriquecimento
from core.contratos import normalizar_severidade
from db import mongo_repo, mysql_repo
from ia import assistente
from ml import classificar
from web import painel, seguranca

api = Blueprint("api", __name__, url_prefix="/api")


def pendente(cenario):
    return jsonify({"erro": "não implementado", "cenario": cenario}), 501


def erro(mensagem, status):
    return jsonify({"erro": mensagem}), status


# ── Rotas ──────────────────────────────────────────────────────

@api.get("/saude")
def saude():
    return jsonify({"status": "online", "servico": "securapy-api"})


@api.get("/eventos")
def listar_eventos():
    """Filtros fonte, tipo, ip, desde, ate + pagina/tamanho (1..PAGINA_TAMANHO_MAX). Inválido → 400.  [D1]"""
    return pendente("D1")


@api.get("/alertas")
def listar_alertas():
    """?severidade=critica&pagina=1&tamanho=5 → {"pagina", "tamanho", "itens"}. Use normalizar_severidade.  [D1]"""
    return pendente("D1")


@api.get("/alertas/<id_alerta>")
def obter_alerta(id_alerta):
    """200 com o alerta · 400 id malformado · 404 inexistente."""
    return pendente("D1")


@api.post("/alertas")
@token_obrigatorio
def criar_alerta():
    """Corpo JSON: ip (válido), severidade (do contrato), descricao (texto). 201 + id · 400 inválido.  [D3][D4]"""
    return pendente("D4")


@api.post("/analisar")
@token_obrigatorio
def analisar():
    """Corpo {} (pasta logs/ inteira), {"caminho": "auth.log"} ou {"eventos": [...]} → orquestrador.executar_analise.
    200 {"resumo", "ameacas"} · caminho fora de logs/ ou lote inválido → 400 (ValueError/FileNotFoundError)."""
    return pendente("D-analisar")


@api.get("/ip/<ip>")
def investigar_ip(ip):
    """Eventos + alertas + geolocalização + score de ML + triagem do LLM. IP malformado → 400.  [D2][D5]"""
    return pendente("D2")


@api.post("/token")
def emitir_token():
    """Email/senha (mysql_repo.autenticar) → {"token": gerar_token(...)}. Falha → 401 genérico."""
    return pendente("D3")


# ── Montagem da aplicação ──────────────────────────────────────

def registrar_erros(app):
    """Handlers 400/404/405/500 em JSON, sem vazar detalhes internos.  [GS 6.2]"""


def criar_app(testando=False):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    app = Flask(
        __name__,
        template_folder=str(settings.RAIZ / "web" / "templates"),
        static_folder=str(settings.RAIZ / "web" / "static"),
    )
    app.config.update(
        SECRET_KEY=settings.SECRET_KEY,
        TESTING=testando,
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    app.json.ensure_ascii = False
    app.json.sort_keys = False

    app.register_blueprint(api)
    app.register_blueprint(painel.web)
    seguranca.registrar(app)
    registrar_erros(app)

    if settings.ALERTAS_TCP_ATIVO and not testando:
        iniciar_em_background(settings.ALERTAS_HOST, settings.ALERTAS_PORTA)
    return app
