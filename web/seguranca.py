"""Endurecimento HTTP aplicado a TODA resposta (API e dashboard)."""

import logging
from flask import request

log_acesso = logging.getLogger("securapy.acesso")

def aplicar_headers(resposta):
    """X-Content-Type-Options: nosniff · X-Frame-Options: DENY · Content-Security-Policy: default-src 'self'. [E2]"""
    # Impede que navegadores tentem "adivinhar" o tipo do arquivo (Mitiga ataques de MIME Sniffing)
    resposta.headers["X-Content-Type-Options"] = "nosniff"
    # Impede que o dashboard seja embutido em um <iframe> de outro site (Mitiga Clickjacking)
    resposta.headers["X-Frame-Options"] = "DENY"
    # Restringe a execução de scripts e recursos apenas para a própria origem (Mitiga XSS)
    resposta.headers["Content-Security-Policy"] = "default-src 'self'"
    
    return resposta

def registrar_acesso(resposta):
    """Uma linha em log_acesso por requisição: IP de origem, método, caminho e status (OWASP A09). [E4]"""
    ip = request.remote_addr
    metodo = request.method
    caminho = request.path
    status = resposta.status_code
    
    # Registra a trilha de auditoria
    log_acesso.info(f"IP: {ip} | Método: {metodo} | Caminho: {caminho} | Status: {status}")
    
    return resposta

def registrar(app):
    app.after_request(aplicar_headers)
    app.after_request(registrar_acesso)