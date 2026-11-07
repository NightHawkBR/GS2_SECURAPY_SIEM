"""Dashboard dos analistas."""

from functools import wraps
from flask import Blueprint, redirect, render_template, request, session, url_for

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
    """POST → mysql_repo.autenticar. Falha → 401. Campos vazios → 400. [E3]"""
    erro = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        senha = request.form.get("senha", "").strip()
        
        # Correção 1: Exigência do teste para campos vazios (Erro 400)
        if not email or not senha:
            erro = "Preencha todos os campos."
            return render_template("login.html", erro=erro), 400
            
        usuario = mysql_repo.autenticar(email, senha)
        if usuario:
            # Correção 2: Exigência do teste de salvar o dicionário inteiro do operador
            session[CHAVE_SESSAO] = usuario
            return redirect(url_for("web.painel"))
        else:
            # Falha genérica anti-enumeração
            erro = MENSAGEM_LOGIN_INVALIDO
            return render_template("login.html", erro=erro), 401
            
    return render_template("login.html", erro=erro)

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
    
    # Enriquecimento (Geolocalização)
    if enriquecimento.eh_ip_privado(ip_alvo):
        geo = {"org": "Rede Interna"}
    else:
        # Passa um cache vazio provisório (a arquitetura principal injetará o oficial)
        geo = enriquecimento.consultar_ip(ip_alvo, cache={})
        
    # Integração Segura: Tenta usar os módulos C e G. 
    # Se os parceiros ainda não codaram, não quebra a tela.
    try:
        classificacao = classificar.classificar(ip_alvo) # Nome presumido da função do Módulo C
    except (NotImplementedError, AttributeError, TypeError):
        classificacao = None

    try:
        triagem = assistente.analisar(eventos, alertas) # Nome presumido da função do Módulo G
    except (NotImplementedError, AttributeError, TypeError):
        triagem = None

    contexto = {
        "ip": ip_alvo,
        "eventos": eventos,
        "alertas": alertas,
        "geo": geo,
        "classificacao": classificacao,
        "triagem": triagem
    }
    return render_template("ip.html", **contexto)