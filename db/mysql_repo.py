"""Repositório MySQL — operadores da plataforma (integridade relacional).

Módulo B · Aulas 3 e 7. Regra de ouro: TODA query parametrizada com %s — nunca f-string em SQL.
Senhas só em hash (werkzeug.security.generate_password_hash / check_password_hash).
"""

import mysql.connector

from config import settings

NIVEIS = range(1, 6)
COLUNAS_PUBLICAS = "id, nome, email, nivel_acesso, criado_em"   # nunca exponha senha_hash


class EmailDuplicadoError(Exception):
    """Email já cadastrado (UNIQUE) — a API responde 409."""


class NivelInvalidoError(ValueError):
    """Nível de acesso fora de 1–5."""


def conectar():
    return mysql.connector.connect(**settings.MYSQL, connection_timeout=5)


def criar_usuario(nome, email, senha, nivel=1, conexao=None) -> int:
    """Grava o operador com senha em hash e devolve o id. Duplicata → EmailDuplicadoError.  [B3]"""
    raise NotImplementedError


def buscar_por_email(email, conexao=None) -> dict | None:
    raise NotImplementedError


def listar_usuarios(conexao=None) -> list[dict]:
    raise NotImplementedError


def atualizar_nivel(usuario_id, nivel, conexao=None) -> bool:
    """Promove/rebaixa. Fora de 1–5 → NivelInvalidoError. False se o id não existe."""
    raise NotImplementedError


def remover_usuario(usuario_id, conexao=None) -> bool:
    raise NotImplementedError


def autenticar(email, senha, conexao=None) -> dict | None:
    """Operador (sem senha_hash) se confere; senão None — sem revelar se errou email ou senha.  [B4][E3]"""
    raise NotImplementedError
