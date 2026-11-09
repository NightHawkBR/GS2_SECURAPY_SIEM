"""API REST — porta de entrada para dashboards, automações e outros sistemas.  Módulo D · Aulas 6, 7 e 10

Produção (Docker):  gunicorn "api.app:criar_app()"
Contrato de erro:   {"erro": "<mensagem amigável>"} — nunca traceback, query ou segredo.
"""

import hashlib
import logging
import re
import uuid
from datetime import datetime

from flask import Blueprint, Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

import orquestrador
from alertas.servidor_alertas import iniciar_em_background
from api.auth import NIVEL_ALERTA_MANUAL, NIVEL_ANALISE, gerar_token, nivel_minimo, token_obrigatorio
from config import settings
from core import enriquecimento
from core.contratos import FONTES, normalizar_severidade
from db import migracao, mongo_repo, mysql_repo
from ia import assistente
from ml import classificar
from web import painel, seguranca

# ── Configuração ──────────────────────────────────────────────────

api = Blueprint("api", __name__, url_prefix="/api")
log = logging.getLogger("securapy.api")

CAMPOS_EVENTO = ("timestamp", "fonte", "tipo", "ip", "detalhes", "linha_original")
FORMATO_DATA_HORA, FORMATO_DATA = "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"
TIPO_EVENTO = re.compile(r"[A-Za-z_]{1,20}")
MAX_EVENTOS_LOTE = 5000
ORDENACOES = ("data", "risco")

# ── Funções auxiliares ────────────────────────────────────────────

def erro(mensagem, status):
    return jsonify({"erro": mensagem}), status


def ler_paginacao():
    try:
        pagina = int(request.args.get("pagina", 1))
        tamanho = int(request.args.get("tamanho", 20))
    except ValueError:
        return None
    if pagina < 1 or not 1 <= tamanho <= settings.PAGINA_TAMANHO_MAX:
        return None
    return pagina, tamanho


def _data(texto, formato):
    try:
        return datetime.strptime(texto, formato)
    except ValueError:
        return None


def ler_periodo():
    """desde/ate em AAAA-MM-DD ou AAAA-MM-DD HH:MM:SS; data sem hora cobre o dia inteiro. Inválido → None."""
    periodo = {}
    for nome, hora in (("desde", "00:00:00"), ("ate", "23:59:59")):
        valor = request.args.get(nome)
        if valor is None:
            continue
        if _data(valor, FORMATO_DATA):
            valor = f"{valor} {hora}"
        elif not _data(valor, FORMATO_DATA_HORA):
            return None
        periodo[nome] = valor
    if periodo.get("desde", "") > periodo.get("ate", "9999"):
        return None
    return periodo


def evento_limpo(evento):
    """Só os 6 campos do contrato, todos texto e coerentes — nada de objeto, lista ou chave extra.  [D4]"""
    if not isinstance(evento, dict) or not all(isinstance(evento.get(campo), str) for campo in CAMPOS_EVENTO):
        return None
    limpo = {campo: evento[campo] for campo in CAMPOS_EVENTO}
    coerente = (
        _data(limpo["timestamp"], FORMATO_DATA_HORA)
        and limpo["fonte"] in FONTES
        and TIPO_EVENTO.fullmatch(limpo["tipo"])
        and enriquecimento.ip_valido(limpo["ip"])
        and limpo["linha_original"].strip()
    )
    return limpo if coerente else None


def obter_geolocalizacao(ip):
    """MongoDB primeiro; IP novo vai ao ipinfo.io e a resposta fica gravada na coleção."""
    return enriquecimento.consultar_ip(ip, mongo_repo.CacheGeolocalizacao())


def obter_score(ip, eventos):
    try:
        return classificar.classificar_ip(ip, eventos)
    except Exception as falha:
        log.warning("score de ML indisponível: %s", type(falha).__name__)
        return None


def obter_triagem(eventos):
    if not eventos:
        return None
    evento = {campo: eventos[0][campo] for campo in CAMPOS_EVENTO if campo in eventos[0]}
    try:
        return assistente.classificar_evento(evento)
    except Exception as falha:
        log.warning("triagem do LLM indisponível: %s", type(falha).__name__)
        return None

# ── Rotas: saúde da API ───────────────────────────────────────────

@api.get("/saude")
def saude():
    return jsonify({"status": "online", "servico": "securapy-api"})

# ── Rotas: eventos ────────────────────────────────────────────────

@api.get("/eventos")
def listar_eventos():
    paginacao = ler_paginacao()
    if paginacao is None:
        return erro("Parâmetros 'pagina' e 'tamanho' inválidos", 400)
    pagina, tamanho = paginacao

    fonte = request.args.get("fonte")
    if fonte is not None and fonte not in FONTES:
        return erro("Fonte inválida", 400)
    ip = request.args.get("ip")
    if ip is not None and not enriquecimento.ip_valido(ip):
        return erro("IP inválido", 400)
    tipo = request.args.get("tipo")
    periodo = ler_periodo()
    if periodo is None:
        return erro("Período inválido: use AAAA-MM-DD ou AAAA-MM-DD HH:MM:SS, com 'desde' antes de 'ate'", 400)

    itens = mongo_repo.buscar_eventos(
        fonte=fonte, tipo=tipo.upper() if tipo else None, ip=ip, **periodo,
        pagina=pagina, tamanho=tamanho,
    )
    return jsonify({"pagina": pagina, "tamanho": tamanho, "itens": itens})

# ── Rotas: alertas ────────────────────────────────────────────────

@api.get("/alertas")
def listar_alertas():
    paginacao = ler_paginacao()
    if paginacao is None:
        return erro("Parâmetros 'pagina' e 'tamanho' inválidos", 400)
    pagina, tamanho = paginacao

    severidade = None
    if "severidade" in request.args:
        severidade = normalizar_severidade(request.args["severidade"])
        if severidade is None:
            return erro("Severidade inválida", 400)
    ip = request.args.get("ip")
    if ip is not None and not enriquecimento.ip_valido(ip):
        return erro("IP inválido", 400)
    ordenar = request.args.get("ordenar", "data")
    if ordenar not in ORDENACOES:
        return erro("Ordenação inválida: use 'data' ou 'risco'", 400)

    itens = mongo_repo.buscar_alertas(severidade=severidade, ip=ip, pagina=pagina, tamanho=tamanho, ordenar=ordenar)
    return jsonify({"pagina": pagina, "tamanho": tamanho, "ordenar": ordenar, "itens": itens})

@api.get("/alertas/<id_alerta>")
def obter_alerta(id_alerta):
    try:
        alerta = mongo_repo.obter_alerta(id_alerta)
    except ValueError:
        return erro("ID de alerta inválido", 400)
    if alerta is None:
        return erro("Alerta não encontrado", 404)
    return jsonify(alerta)

@api.post("/alertas")
@token_obrigatorio
@nivel_minimo(NIVEL_ALERTA_MANUAL)
def criar_alerta():
    dados = request.get_json(silent=True)
    if not isinstance(dados, dict):
        return erro("Corpo JSON obrigatório", 400)

    ip = dados.get("ip")
    descricao = dados.get("descricao")
    severidade = normalizar_severidade(dados.get("severidade"))
    if not isinstance(ip, str) or not enriquecimento.ip_valido(ip):
        return erro("IP inválido", 400)
    if severidade is None:
        return erro("Severidade inválida", 400)
    if not isinstance(descricao, str) or not descricao.strip():
        return erro("Campo 'descricao' é obrigatório", 400)

    alerta = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "regra_id": "MANUAL",
        "regra_nome": "Alerta manual",
        "severidade": severidade,
        "ip": ip,
        "descricao": descricao.strip(),
        "criado_por": g.operador["sub"],
        "hash": hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
    }
    return jsonify({"id": mongo_repo.inserir_alerta(alerta)}), 201

@api.get("/ameacas")
def listar_ameacas():
    """Ameaças priorizadas pelo ML: score do IP, depois a pontuação das regras.  [C3]"""
    paginacao = ler_paginacao()
    if paginacao is None:
        return erro("Parâmetros 'pagina' e 'tamanho' inválidos", 400)
    _, tamanho = paginacao
    return jsonify({"itens": mongo_repo.listar_ameacas(n=tamanho)})

# ── Rotas: análise dos logs ───────────────────────────────────────

@api.post("/analisar")
@token_obrigatorio
@nivel_minimo(NIVEL_ANALISE)
def analisar():
    dados = request.get_json(silent=True)
    if dados is None and not request.get_data():
        dados = {}
    if not isinstance(dados, dict):
        return erro("Corpo JSON inválido", 400)

    caminho = dados.get("caminho")
    eventos = dados.get("eventos")

    if caminho is not None and not isinstance(caminho, str):
        return erro("Campo 'caminho' deve ser texto", 400)
    if eventos is not None:
        if not isinstance(eventos, list) or not eventos:
            return erro("Campo 'eventos' deve ser uma lista não vazia", 400)
        if len(eventos) > MAX_EVENTOS_LOTE:
            return erro(f"Lote acima de {MAX_EVENTOS_LOTE} eventos", 400)
        limpos = [evento_limpo(e) for e in eventos]
        if None in limpos:
            posicao = limpos.index(None) + 1
            return erro(f"Evento {posicao} fora do formato esperado", 400)
        eventos = limpos

    try:
        resultado = orquestrador.executar_analise(caminho=caminho, eventos=eventos)
    except (ValueError, FileNotFoundError):
        return erro("Caminho de log inválido ou fora da pasta de logs", 400)
    return jsonify({"resumo": resultado["resumo"], "ameacas": resultado["ameacas"]})

# ── Rotas: investigação de IP ─────────────────────────────────────

@api.get("/ip/<ip>")
def investigar_ip(ip):
    if not enriquecimento.ip_valido(ip):
        return erro("IP inválido", 400)

    eventos = mongo_repo.buscar_eventos(ip=ip, pagina=1, tamanho=settings.PAGINA_TAMANHO_MAX)
    alertas = mongo_repo.buscar_alertas(ip=ip, pagina=1, tamanho=settings.PAGINA_TAMANHO_MAX)
    classificacao = obter_score(ip, eventos)
    ameaca = mongo_repo.obter_ameaca(ip)

    return jsonify({
        "ip": ip,
        "eventos": eventos,
        "alertas": alertas,
        "geolocalizacao": obter_geolocalizacao(ip),
        "score": classificacao["score"] if classificacao else None,
        "rotulo_ml": classificacao["rotulo"] if classificacao else None,
        "anomalia": any(a.get("anomalia") for a in alertas) or bool(ameaca and ameaca.get("anomalia")),
        "ameaca": ameaca,
        "triagem": obter_triagem(eventos),
    })

# ── Rotas: autenticação ───────────────────────────────────────────

@api.post("/token")
def emitir_token():
    dados = request.get_json(silent=True)
    if not isinstance(dados, dict):
        return erro("Corpo JSON obrigatório", 400)
    email = dados.get("email")
    senha = dados.get("senha")
    if not isinstance(email, str) or not isinstance(senha, str) or not email or not senha:
        return erro("Informe email e senha", 400)

    operador = mysql_repo.autenticar(email, senha)
    if operador is None:
        return erro("Credenciais inválidas", 401)
    return jsonify({
        "token": gerar_token(operador["email"], operador.get("nivel_acesso", 1)),
        "tipo": "Bearer",
        "expira_em": settings.JWT_EXPIRA_MINUTOS * 60,
    })

# ── Tratamento de erros ───────────────────────────────────────────

def registrar_erros(app):
    mensagens = {
        400: "Requisição inválida",
        404: "Rota não existe",
        405: "Método não permitido",
        413: "Corpo da requisição grande demais",
        500: "Erro interno do servidor",
    }

    def responder(e):
        codigo = e.code if isinstance(e, HTTPException) else 500
        if not request.path.startswith("/api/"):
            return e if isinstance(e, HTTPException) else ("Erro interno do servidor", 500)
        if codigo == 500:
            causa = getattr(e, "original_exception", None) or e
            log.error("erro em %s %s: %s", request.method, request.path, type(causa).__name__)
        return erro(mensagens.get(codigo, "Erro na requisição"), codigo)

    for codigo in mensagens:
        app.register_error_handler(codigo, responder)

# ── Montagem da aplicação ─────────────────────────────────────────

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
    app.json.mimetype = "application/json; charset=utf-8"
    app.json.sort_keys = False

    app.register_blueprint(api)
    app.register_blueprint(painel.web)
    seguranca.registrar(app)
    registrar_erros(app)

    if not testando:
        migracao.preparar_banco()
    if settings.ALERTAS_TCP_ATIVO and not testando:
        iniciar_em_background(settings.ALERTAS_HOST, settings.ALERTAS_PORTA)
    return app
