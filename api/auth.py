"""Autenticação por token Bearer nas rotas de escrita.  Módulo D · Aula 10 (JWT completo = bônus +0,20)"""

import hmac
from functools import wraps

from flask import jsonify, request

from config import settings


def gerar_token(operador: str) -> str:
    """Token do operador autenticado: o API_TOKEN configurado no ambiente."""
    return settings.API_TOKEN or ""


def validar_token(token: str) -> bool:
    """hmac.compare_digest (tempo constante). Sem API_TOKEN configurado → rejeita tudo."""
    if not settings.API_TOKEN or not token:
        return False
    return hmac.compare_digest(token.encode("utf-8"), settings.API_TOKEN.encode("utf-8"))


def token_obrigatorio(view):
    """Exige 'Authorization: Bearer <token>' válido; ausente ou inválido → 401.  [D3]"""
    @wraps(view)
    def protegida(*args, **kwargs):
        esquema, _, token = request.headers.get("Authorization", "").partition(" ")
        if esquema != "Bearer" or not validar_token(token.strip()):
            return jsonify({"erro": "Token ausente ou inválido"}), 401
        return view(*args, **kwargs)
    return protegida
