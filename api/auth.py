"""Autenticação Bearer nas rotas de escrita.  Módulo D · Aula 10 · bônus JWT (+0,20)

Dois tipos de token:
  • JWT do operador — emitido em POST /api/token após o login, assinado (HS256) e com validade curta;
  • token de serviço — API_TOKEN do .env, para automações (vazio = desativado).
"""

import hmac
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, jsonify, request

from config import settings

ALGORITMO = "HS256"
EMISSOR = "securapy"
CLAIMS_OBRIGATORIAS = ["sub", "nivel", "iss", "iat", "exp"]

# níveis 1–5 do MySQL: 1 só consulta · 2+ registra alerta manual · 3+ dispara a análise completa
NIVEL_ALERTA_MANUAL = 2
NIVEL_ANALISE = 3


def gerar_token(email: str, nivel: int = 1) -> str:
    """JWT com quem é (sub), nível de acesso, emissor, emissão e expiração."""
    agora = datetime.now(timezone.utc)
    claims = {
        "sub": email,
        "nivel": int(nivel),
        "iss": EMISSOR,
        "iat": agora,
        "exp": agora + timedelta(minutes=settings.JWT_EXPIRA_MINUTOS),
    }
    return jwt.encode(claims, settings.JWT_SECRET, algorithm=ALGORITMO)


def decodificar_token(token: str) -> dict | None:
    """Claims se assinatura, emissor e validade conferem; senão None."""
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[ALGORITMO],          # lista fixa: bloqueia "alg: none" e troca de algoritmo
            issuer=EMISSOR,
            options={"require": CLAIMS_OBRIGATORIAS},
        )
    except jwt.InvalidTokenError:
        return None


def _token_de_servico(token: str) -> bool:
    return bool(settings.API_TOKEN) and hmac.compare_digest(token.encode(), settings.API_TOKEN.encode())


def identificar(token: str) -> dict | None:
    """Quem está chamando: claims do JWT, identidade de serviço ou None."""
    if not token:
        return None
    if _token_de_servico(token):
        return {"sub": "servico", "nivel": 5}
    return decodificar_token(token)


def validar_token(token: str) -> bool:
    return identificar(token) is not None


def token_obrigatorio(view):
    """Exige 'Authorization: Bearer <token>' válido; ausente, expirado ou adulterado → 401.  [D3]"""
    @wraps(view)
    def protegida(*args, **kwargs):
        esquema, _, token = request.headers.get("Authorization", "").partition(" ")
        identidade = identificar(token.strip()) if esquema.lower() == "bearer" else None
        if identidade is None:
            return jsonify({"erro": "Token ausente ou inválido"}), 401
        g.operador = identidade
        return view(*args, **kwargs)
    return protegida


def nivel_minimo(nivel):
    """Vem depois do token_obrigatorio: operador abaixo do nível exigido → 403."""
    def decorador(view):
        @wraps(view)
        def protegida(*args, **kwargs):
            if int(g.operador.get("nivel", 0)) < nivel:
                return jsonify({"erro": "Nível de acesso insuficiente"}), 403
            return view(*args, **kwargs)
        return protegida
    return decorador
