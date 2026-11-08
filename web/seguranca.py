"""Endurecimento HTTP aplicado a TODA resposta (API e dashboard).  Módulo E · Aula 8"""

import logging

from flask import request

log_acesso = logging.getLogger("securapy.acesso")

HEADERS_SEGURANCA = {
    "X-Content-Type-Options": "nosniff",               # sem MIME sniffing
    "X-Frame-Options": "DENY",                         # sem clickjacking
    "Content-Security-Policy": "default-src 'self'",   # só recursos da própria origem (XSS)
}


def aplicar_headers(resposta):
    """Headers de segurança em toda resposta.  [E2]"""
    resposta.headers.update(HEADERS_SEGURANCA)
    return resposta


def registrar_acesso(resposta):
    """Uma linha por requisição: IP de origem, método, caminho e status (OWASP A09).  [E4]"""
    log_acesso.info("IP: %s | Método: %s | Caminho: %s | Status: %s",
                    request.remote_addr, request.method, request.path, resposta.status_code)
    return resposta


def registrar(app):
    app.after_request(aplicar_headers)
    app.after_request(registrar_acesso)
