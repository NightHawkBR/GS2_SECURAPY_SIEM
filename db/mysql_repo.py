"""Repositório MySQL — operadores da plataforma (integridade relacional)."""

import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from config import settings

NIVEIS = range(1, 6)
COLUNAS_PUBLICAS = "id, nome, email, nivel_acesso, criado_em"

class EmailDuplicadoError(Exception):
    """Email já cadastrado (UNIQUE)."""

class NivelInvalidoError(ValueError):
    """Nível de acesso fora de 1–5."""

def conectar():
    return mysql.connector.connect(**settings.MYSQL, connection_timeout=5)

def criar_usuario(nome, email, senha, nivel=1, conexao=None) -> int:
    """Grava o operador com senha em hash e devolve o id. Duplicata → EmailDuplicadoError."""
    if int(nivel) not in NIVEIS:
        raise NivelInvalidoError(f"Nível de acesso {nivel} inválido. Deve ser entre 1 e 5.")
        
    con = conexao if conexao else conectar()
    senha_hash = generate_password_hash(senha)
    
    try:
        cursor = con.cursor()
        query = "INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (nome, email, senha_hash, str(nivel)))
        con.commit()
        return cursor.lastrowid
    except mysql.connector.IntegrityError:
        raise EmailDuplicadoError(f"O email {email} já está cadastrado.")
    finally:
        cursor.close()
        if not conexao: con.close()

def autenticar(email, senha, conexao=None) -> dict | None:
    """Operador (sem senha_hash) se confere; senão None — sem revelar se errou email ou senha. [B4][E3]"""
    con = conexao if conexao else conectar()
    try:
        cursor = con.cursor(dictionary=True)
        query = f"SELECT id, nome, email, nivel_acesso, senha_hash FROM usuarios WHERE email = %s"
        cursor.execute(query, (email,))
        usuario = cursor.fetchone()
        
        if usuario and check_password_hash(usuario["senha_hash"], senha):
            del usuario["senha_hash"]
            return usuario
        return None
    finally:
        cursor.close()
        if not conexao: con.close()
