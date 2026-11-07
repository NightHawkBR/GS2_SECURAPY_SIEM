"""Dashboard dos analistas.  Módulo E · Aulas 6 e 8

Jinja2 escapa tudo por padrão: nunca use |safe nem Markup com dado vindo de log ou do banco.
"""

from functools import wraps

from flask import Blueprint, redirect, render_template, request, session, url_for

from core import enriquecimento
from db import mongo_repo, mysql_repo
from ia import assistente
from ml import classificar

web = Blueprint("web", __name__)

CHAVE_SESSAO = "operador"
MENSAGEM_LOGIN_INVALIDO = "Credenciais inválidas."


def pendente(cenario):
    return render_template("pendente.html", cenario=cenario), 501


def login_obrigatorio(view):
    """Sem session[CHAVE_SESSAO] → redireciona para /login."""
    @wraps(view)
    def protegida(*args, **kwargs):
        return pendente("E3")
    return protegida


@web.get("/")
def inicio():
    return redirect(url_for("web.painel"))


@web.route("/login", methods=["GET", "POST"])
def login():
    """POST → mysql_repo.autenticar. Falha → 401 com MENSAGEM_LOGIN_INVALIDO (mesma p/ usuário e senha).  [E3]"""
    return pendente("E3")


@web.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("web.login"))


@web.get("/painel")
@login_obrigatorio
def painel():
    """Contexto do template: por_fonte, por_severidade, top_ips, alertas_recentes.  [E1]"""
    return pendente("E1")


@web.get("/painel/ip")
@login_obrigatorio
def painel_ip():
    """?ip=... → contexto: ip, eventos, alertas, geo, classificacao, triagem."""
    return pendente("E1")
