"""Autenticação por token Bearer nas rotas de escrita.  Módulo D · Aula 10 (JWT completo = bônus +0,20)"""

from functools import wraps

from flask import jsonify, request

from config import settings


def gerar_token(operador: str) -> str:
    """Token do operador autenticado: settings.API_TOKEN (estático) ou JWT assinado com SECRET_KEY."""
    raise NotImplementedError


def validar_token(token: str) -> bool:
    """hmac.compare_digest (tempo constante) — ou assinatura + expiração do JWT. Sem API_TOKEN → rejeita tudo."""
    raise NotImplementedError


def token_obrigatorio(view):
    """Exige 'Authorization: Bearer <token>' válido; ausente ou inválido → 401.  [D3]"""
    @wraps(view)
    def protegida(*args, **kwargs):
        return jsonify({"erro": "não implementado", "cenario": "D3"}), 501   # fail-closed até implementar
    return protegida
