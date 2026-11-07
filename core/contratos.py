"""Contratos de dados entre as camadas — a "cola" da plataforma (GS §8, dica 2).

Toda camada (db, ml, api, web, ia) troca dados nestes formatos. Mudou aqui? Avise a equipe.
"""

import unicodedata
from typing import Literal, TypedDict

Fonte = Literal["auth", "firewall", "web"]
Severidade = Literal["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"]
RotuloLLM = Literal["NORMAL", "SUSPEITO", "CRITICO"]
RotuloML = Literal["normal", "ataque"]

FONTES: tuple[Fonte, ...] = ("auth", "firewall", "web")
SEVERIDADES: tuple[Severidade, ...] = ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO")
ROTULOS_LLM: tuple[RotuloLLM, ...] = ("NORMAL", "SUSPEITO", "CRITICO")
ROTULOS_ML: tuple[RotuloML, ...] = ("normal", "ataque")


class Evento(TypedDict):
    timestamp: str                  # "AAAA-MM-DD HH:MM:SS" — ordena como texto
    fonte: Fonte
    tipo: str                       # OK | FAIL | BLOCK | ALLOW | GET | POST | DELETE ...
    ip: str
    detalhes: str                   # "chave=valor chave=valor"
    linha_original: str


class Alerta(TypedDict, total=False):
    timestamp: str
    regra_id: str                   # R001..R005 ou "MANUAL" (POST /api/alertas)
    regra_nome: str
    severidade: Severidade
    ip: str
    descricao: str
    geolocalizacao: dict            # opcional — core.enriquecimento


class Ameaca(TypedDict, total=False):
    ip: str
    deteccoes: list[str]            # brute_force | port_scan | blacklist
    pontuacao: int
    severidade: Severidade
    detalhes: dict
    score: float | None             # preenchido pelo ML (0.0 a 1.0)
    rotulo_ml: RotuloML | None


class Classificacao(TypedDict):     # saída de ml.classificar
    ip: str
    score: float
    rotulo: RotuloML


class Triagem(TypedDict):           # saída de ia.assistente
    rotulo: RotuloLLM
    explicacao: str
    origem: Literal["llm", "fallback"]


def normalizar_severidade(valor):
    """'critica', 'Crítica', 'CRITICA' → 'CRITICA'. Valor fora do contrato → None."""
    if not isinstance(valor, str):
        return None
    texto = unicodedata.normalize("NFKD", valor).encode("ascii", "ignore").decode().strip().upper()
    return texto if texto in SEVERIDADES else None


def serializavel(obj):
    """Converte sets em listas ordenadas (recursivo) — necessário para JSON e MongoDB."""
    if isinstance(obj, dict):
        return {chave: serializavel(valor) for chave, valor in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [serializavel(item) for item in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted(serializavel(item) for item in obj)
    return obj
