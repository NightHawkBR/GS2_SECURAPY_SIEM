"""Dashboard dos analistas."""

from functools import wraps
from flask import Blueprint, redirect, render_template, request, session, url_for

from config import settings
from core import enriquecimento
from db import mongo_repo, mysql_repo
from ia import assistente
from ml import classificar

web = Blueprint("web", __name__)

CHAVE_SESSAO = "operador"
MENSAGEM_LOGIN_INVALIDO = "Credenciais inválidas."

def login_obrigatorio(view):
    """Sem session[CHAVE_SESSAO] → redireciona para /login."""
    @wraps(view)
    def protegida(*args, **kwargs):
        if CHAVE_SESSAO not in session:
            return redirect(url_for("web.login"))
        return view(*args, **kwargs)
    return protegida

@web.get("/")
def inicio():
    return redirect(url_for("web.painel"))

@web.route("/login", methods=["GET", "POST"])
def login():
    """POST → mysql_repo.autenticar. Falha → 401. Campos vazios → 400.  [E3]"""
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip()
    senha = request.form.get("senha", "")
    if not email or not senha:
        return render_template("login.html", erro="Preencha todos os campos."), 400

    operador = mysql_repo.autenticar(email, senha)
    if not operador:                     # mesma resposta para email inexistente e senha errada
        return render_template("login.html", erro=MENSAGEM_LOGIN_INVALIDO), 401

    session.clear()                      # sessão nova a cada login (evita session fixation)
    session[CHAVE_SESSAO] = operador
    return redirect(url_for("web.painel"))


@web.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("web.login"))

@web.get("/painel")
@login_obrigatorio
def painel():
    """Contexto do template: por_fonte, por_severidade, top_ips, alertas_recentes. [E1]"""
    contexto = {
        "por_fonte": mongo_repo.contagem_por_fonte(),
        "por_severidade": mongo_repo.contagem_por_severidade(),
        "top_ips": mongo_repo.top_ips(n=10),
        "alertas_recentes": mongo_repo.buscar_alertas(tamanho=10)
    }
    return render_template("painel.html", **contexto)

@web.get("/painel/ip")
@login_obrigatorio
def painel_ip():
    """?ip=... → contexto: ip, eventos, alertas, geo, classificacao, triagem."""
    ip_alvo = request.args.get("ip")
    if not ip_alvo:
        return redirect(url_for("web.painel"))

    eventos = mongo_repo.buscar_eventos(ip=ip_alvo, tamanho=50)
    alertas = mongo_repo.buscar_alertas(ip=ip_alvo, tamanho=50)
    geo = enriquecimento.consultar_ip(ip_alvo, enriquecimento.carregar_cache(settings.ARQUIVO_CACHE_GEO))

    try:
        classificacao = classificar.classificar_ip(ip_alvo, eventos)
    except Exception:   # modelo ausente ou adulterado: a tela continua sem o score
        classificacao = None
    triagem = assistente.classificar_evento(eventos[0]) if eventos else None

    contexto = {
        "ip": ip_alvo,
        "eventos": eventos,
        "alertas": alertas,
        "geo": geo,
        "classificacao": classificacao,
        "triagem": triagem
    }
    return render_template("ip.html", **contexto)
