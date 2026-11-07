"""Endurecimento HTTP aplicado a TODA resposta (API e dashboard).  Módulo E · Aula 8

Os hooks devolvem a resposta intacta até serem implementados — assim a aplicação continua no ar.
"""

import logging

from flask import request

log_acesso = logging.getLogger("securapy.acesso")


def aplicar_headers(resposta):
    """X-Content-Type-Options: nosniff · X-Frame-Options: DENY · Content-Security-Policy: default-src 'self'.  [E2]"""
    return resposta


def registrar_acesso(resposta):
    """Uma linha em log_acesso por requisição: IP de origem, método, caminho e status (OWASP A09).  [E4]"""
    return resposta


def registrar(app):
    app.after_request(aplicar_headers)
    app.after_request(registrar_acesso)
