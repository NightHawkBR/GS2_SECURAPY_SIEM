"""Configuração central. Tudo vem de variáveis de ambiente — segredos nunca no código (Aulas 2, 10 e 13)."""

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

RAIZ = Path(__file__).resolve().parent.parent
load_dotenv(RAIZ / ".env", override=False)   # execução local; no Docker o compose injeta o ambiente


def _env(nome, padrao=None):
    return os.environ.get(nome) or padrao


# ── Dados do núcleo ────────────────────────────────────────────
PASTA_LOGS = Path(_env("SECURAPY_LOGS", RAIZ / "logs"))
ARQUIVO_REGRAS = RAIZ / "config" / "regras.json"
ARQUIVO_CACHE_GEO = RAIZ / "config" / "cache_enriq.json"
PASTA_SAIDA = RAIZ / "saida"
BLACKLIST = frozenset({"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"})

# ── Persistência ───────────────────────────────────────────────
MONGO_URI = _env("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB = _env("MONGO_DB", "securapy")
MYSQL = {
    "host": _env("MYSQL_HOST", "localhost"),
    "port": int(_env("MYSQL_PORT", "3306")),
    "user": _env("MYSQL_USER", "securapy"),
    "password": _env("MYSQL_PASSWORD", ""),
    "database": _env("MYSQL_DATABASE", "securapy"),
}

# ── Machine Learning ───────────────────────────────────────────
MODELO_ML = Path(_env("MODELO_ML", RAIZ / "ml" / "modelo.pkl"))
HASH_MODELO = MODELO_ML.with_suffix(".sha256")
METRICAS_ML = MODELO_ML.with_name("metricas.json")

# ── API e web ──────────────────────────────────────────────────
API_TOKEN = _env("API_TOKEN")
SECRET_KEY = _env("SECRET_KEY") or secrets.token_hex(32)
PAGINA_TAMANHO_MAX = 100

# ── LLM ────────────────────────────────────────────────────────
OPENAI_API_KEY = _env("OPENAI_API_KEY")
OPENAI_MODEL = _env("OPENAI_MODEL", "gpt-4o-mini")
LLM_MODO = _env("LLM_MODO", "auto")            # auto | mock

# ── Alertas em tempo real ──────────────────────────────────────
ALERTAS_HOST = _env("ALERTAS_HOST", "0.0.0.0")
ALERTAS_PORTA = int(_env("ALERTAS_PORTA", "9999"))
ALERTAS_TCP_ATIVO = _env("ALERTAS_TCP_ATIVO", "0") == "1"
ALERTAS_TEMPO_REAL = frozenset({"CRITICA", "ALTA"})
