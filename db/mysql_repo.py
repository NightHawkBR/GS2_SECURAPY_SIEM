"""Repositório MySQL — operadores da plataforma (integridade relacional).  Módulo B · Aulas 3 e 7

Toda query é parametrizada com %s: a entrada do usuário nunca vira parte do SQL.
Senhas só em hash (werkzeug). Erros de conexão sobem como mysql.connector.Error.
"""

from contextlib import contextmanager
from functools import lru_cache

import mysql.connector
from mysql.connector import errorcode
from werkzeug.security import check_password_hash, generate_password_hash

from config import settings

NIVEIS = range(1, 6)

SQL = {
    "inserir": "INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) VALUES (%s, %s, %s, %s)",
    "por_email": "SELECT id, nome, email, nivel_acesso, criado_em FROM usuarios WHERE email = %s",
    "listar": "SELECT id, nome, email, nivel_acesso, criado_em FROM usuarios ORDER BY nome",
    "atualizar_nivel": "UPDATE usuarios SET nivel_acesso = %s WHERE id = %s",
    "remover": "DELETE FROM usuarios WHERE id = %s",
    "credenciais": "SELECT id, nome, email, nivel_acesso, senha_hash FROM usuarios WHERE email = %s",
}


class EmailDuplicadoError(Exception):
    """Email já cadastrado (UNIQUE) — a API responde 409."""


class NivelInvalidoError(ValueError):
    """Nível de acesso fora de 1–5."""


def conectar():
    return mysql.connector.connect(**settings.MYSQL, connection_timeout=5)


@contextmanager
def _cursor(conexao=None, dicionario=False):
    """Fecha cursor e conexão mesmo com erro — o erro original sempre chega a quem chamou."""
    con = conexao if conexao is not None else conectar()
    try:
        with con.cursor(dictionary=dicionario) as cursor:
            yield con, cursor
    finally:
        if conexao is None:
            con.close()


def _nivel_valido(nivel) -> int:
    try:
        nivel = int(nivel)
    except (TypeError, ValueError):
        raise NivelInvalidoError(f"Nível de acesso inválido: {nivel!r}") from None
    if nivel not in NIVEIS:
        raise NivelInvalidoError(f"Nível de acesso {nivel} fora de 1–5")
    return nivel


@lru_cache(maxsize=1)
def _hash_ficticio():
    return generate_password_hash("securapy-operador-inexistente")


# ── CRUD ───────────────────────────────────────────────────────

def criar_usuario(nome, email, senha, nivel=1, conexao=None) -> int:
    """Grava o operador com senha em hash e devolve o id. Duplicata → EmailDuplicadoError.  [B3]"""
    nivel = _nivel_valido(nivel)
    with _cursor(conexao) as (con, cursor):
        try:
            cursor.execute(SQL["inserir"], (nome, email, generate_password_hash(senha), nivel))
            con.commit()
        except mysql.connector.IntegrityError as erro:
            con.rollback()
            if erro.errno == errorcode.ER_DUP_ENTRY:
                raise EmailDuplicadoError(f"O email {email} já está cadastrado.") from None
            raise
        return cursor.lastrowid


def buscar_por_email(email, conexao=None) -> dict | None:
    with _cursor(conexao, dicionario=True) as (_, cursor):
        cursor.execute(SQL["por_email"], (email,))
        return cursor.fetchone()


def listar_usuarios(conexao=None) -> list[dict]:
    with _cursor(conexao, dicionario=True) as (_, cursor):
        cursor.execute(SQL["listar"])
        return cursor.fetchall()


def atualizar_nivel(usuario_id, nivel, conexao=None) -> bool:
    """Promove/rebaixa. Fora de 1–5 → NivelInvalidoError. False se o id não existe."""
    nivel = _nivel_valido(nivel)
    with _cursor(conexao) as (con, cursor):
        cursor.execute(SQL["atualizar_nivel"], (nivel, usuario_id))
        con.commit()
        return cursor.rowcount > 0


def remover_usuario(usuario_id, conexao=None) -> bool:
    with _cursor(conexao) as (con, cursor):
        cursor.execute(SQL["remover"], (usuario_id,))
        con.commit()
        return cursor.rowcount > 0


# ── Autenticação ───────────────────────────────────────────────

def autenticar(email, senha, conexao=None) -> dict | None:
    """Operador (sem senha_hash) se confere; senão None — sem revelar se errou email ou senha.  [B4][E3]"""
    with _cursor(conexao, dicionario=True) as (_, cursor):
        cursor.execute(SQL["credenciais"], (email,))
        usuario = cursor.fetchone()

    # email inexistente também paga o custo do hash: o tempo de resposta não denuncia quem existe
    senha_hash = usuario.pop("senha_hash") if usuario else _hash_ficticio()
    return usuario if check_password_hash(senha_hash, senha) and usuario else None
