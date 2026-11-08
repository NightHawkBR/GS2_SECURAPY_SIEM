"""Módulo B — Persistência. Cenários B1–B4 da GS.

MongoDB: mongomock (em memória). MySQL: conexão simulada com MagicMock — dá para provar
que a query é parametrizada sem subir banco nenhum.
"""

from unittest.mock import MagicMock

import mysql.connector
import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from core.regras import aplicar_regras, carregar_regras
from db import mongo_repo, mysql_repo
from db.migracao import migrar

pytestmark = pytest.mark.persistencia

INJECAO = "' OR '1'='1"


# ── MongoDB ────────────────────────────────────────────────────

class TestMongo:

    def test_b1_ingere_os_58_eventos(self, mongo_fake, pasta_logs):
        assert migrar(pasta_logs) == 58
        eventos = mongo_fake[mongo_repo.EVENTOS]
        assert eventos.count_documents({}) == 58
        assert eventos.count_documents({"fonte": "auth"}) == 23
        assert eventos.count_documents({"fonte": "firewall"}) == 17
        assert eventos.count_documents({"fonte": "web"}) == 18

    def test_b1_reingestao_nao_duplica(self, mongo_fake, pasta_logs):
        migrar(pasta_logs)
        assert migrar(pasta_logs) == 0
        assert mongo_fake[mongo_repo.EVENTOS].count_documents({}) == 58

    def test_b1_indices_em_ip_e_timestamp(self, mongo_fake):
        mongo_repo.criar_indices()
        indices = mongo_fake[mongo_repo.EVENTOS].index_information().values()
        campos = {campo for indice in indices for campo, _ in indice["key"]}
        assert {"ip", "timestamp"} <= campos

    def test_b2_top_ips(self, mongo_fake, eventos_reais):
        mongo_repo.salvar_eventos(eventos_reais)
        ranking = mongo_repo.top_ips(5)
        assert len(ranking) == 5
        assert ranking[0] == {"ip": "185.220.101.1", "total": 25}

    def test_nao_altera_os_dicts_recebidos(self, mongo_fake, eventos_reais):
        mongo_repo.salvar_eventos(eventos_reais)
        assert "_id" not in eventos_reais[0]

    def test_busca_com_filtros_e_contrato_de_saida(self, mongo_fake, eventos_reais):
        mongo_repo.salvar_eventos(eventos_reais)
        falhas = mongo_repo.buscar_eventos(tipo="FAIL", ip="185.220.101.1", tamanho=100)
        assert len(falhas) == 11
        assert all(e["tipo"] == "FAIL" and e["ip"] == "185.220.101.1" for e in falhas)
        assert all("_id" not in e and isinstance(e["id"], str) for e in falhas)

    def test_busca_paginada_mais_recentes_primeiro(self, mongo_fake, eventos_reais):
        mongo_repo.salvar_eventos(eventos_reais)
        pagina1 = mongo_repo.buscar_eventos(pagina=1, tamanho=10)
        pagina2 = mongo_repo.buscar_eventos(pagina=2, tamanho=10)
        assert len(pagina1) == len(pagina2) == 10
        assert pagina1[0]["timestamp"] >= pagina1[-1]["timestamp"] >= pagina2[0]["timestamp"]
        assert not {e["id"] for e in pagina1} & {e["id"] for e in pagina2}

    def test_contagens_do_dashboard(self, mongo_fake, eventos_reais, caminho_regras):
        mongo_repo.salvar_eventos(eventos_reais)
        mongo_repo.salvar_alertas(aplicar_regras(eventos_reais, carregar_regras(caminho_regras)))
        assert mongo_repo.contagem_por_fonte() == {"auth": 23, "firewall": 17, "web": 18}
        assert mongo_repo.contagem_por_severidade() == {"CRITICA": 1, "ALTA": 10, "MEDIA": 20}

    def test_alerta_avulso_e_id_malformado(self, mongo_fake):
        novo = mongo_repo.inserir_alerta({"timestamp": "2025-02-20 09:00:00", "regra_id": "MANUAL",
                                          "regra_nome": "Manual", "severidade": "ALTA",
                                          "ip": "45.33.32.156", "descricao": "teste"})
        assert mongo_repo.obter_alerta(novo)["descricao"] == "teste"
        assert mongo_repo.obter_alerta("0" * 24) is None
        with pytest.raises(ValueError):
            mongo_repo.obter_alerta("id-invalido")


# ── MySQL ──────────────────────────────────────────────────────

def _conexao_falsa(linha=None, erro=None):
    conexao = MagicMock()
    cursor = MagicMock()
    cursor.fetchone.return_value = linha
    cursor.lastrowid = 1
    if erro:
        cursor.execute.side_effect = erro
    conexao.cursor.return_value = cursor
    cursor.__enter__.return_value = cursor
    return conexao, cursor


def _sql_e_parametros(cursor):
    return [(chamada.args[0], chamada.args[1] if len(chamada.args) > 1 else ()) for chamada in cursor.execute.call_args_list]


class TestMySQL:

    def test_cria_usuario_com_senha_em_hash(self):
        conexao, cursor = _conexao_falsa()
        mysql_repo.criar_usuario("Ana Costa", "ana@empresa.com", "Cyber@2024", 5, conexao=conexao)
        (sql, parametros), *_ = _sql_e_parametros(cursor)
        assert "%s" in sql and "Cyber@2024" not in sql
        assert "Cyber@2024" not in parametros
        assert any(isinstance(p, str) and check_password_hash(p, "Cyber@2024") for p in parametros)
        conexao.commit.assert_called()

    def test_b3_email_duplicado_e_tratado(self):
        duplicata = mysql.connector.IntegrityError("Duplicate entry", errno=1062)
        conexao, _ = _conexao_falsa(erro=duplicata)
        with pytest.raises(mysql_repo.EmailDuplicadoError):
            mysql_repo.criar_usuario("Carlos", "carlos@empresa.com", "S3gur4nca!", 3, conexao=conexao)

    @pytest.mark.parametrize("nivel", [0, 6, 9])
    def test_nivel_fora_de_1_a_5(self, nivel):
        conexao, cursor = _conexao_falsa()
        with pytest.raises(mysql_repo.NivelInvalidoError):
            mysql_repo.criar_usuario("Bruno", "bruno@empresa.com", "S3gur4nca!", nivel, conexao=conexao)
        cursor.execute.assert_not_called()

    def test_b4_sql_injection_neutralizada(self):
        conexao, cursor = _conexao_falsa(linha=None)
        assert mysql_repo.autenticar(INJECAO, "qualquer", conexao=conexao) is None
        chamadas = _sql_e_parametros(cursor)
        assert chamadas, "autenticar deve consultar o banco"
        assert all(INJECAO not in sql for sql, _ in chamadas)
        assert any(INJECAO in parametros for _, parametros in chamadas)

    def test_autenticar_confere_hash_e_nao_devolve_senha(self):
        linha = {"id": 1, "nome": "Ana", "email": "ana@empresa.com", "nivel_acesso": 5,
                 "senha_hash": generate_password_hash("Cyber@2024")}
        conexao, _ = _conexao_falsa(linha=dict(linha))
        operador = mysql_repo.autenticar("ana@empresa.com", "Cyber@2024", conexao=conexao)
        assert operador["email"] == "ana@empresa.com" and "senha_hash" not in operador

        conexao, _ = _conexao_falsa(linha=dict(linha))
        assert mysql_repo.autenticar("ana@empresa.com", "errada", conexao=conexao) is None

    def test_outro_erro_de_integridade_nao_vira_duplicata(self):
        nulo = mysql.connector.IntegrityError("Column 'nome' cannot be null", errno=1048)
        conexao, _ = _conexao_falsa(erro=nulo)
        with pytest.raises(mysql.connector.IntegrityError):
            mysql_repo.criar_usuario(None, "x@empresa.com", "S3gur4nca!", 1, conexao=conexao)

    def test_busca_e_listagem_nunca_leem_a_senha(self):
        conexao, cursor = _conexao_falsa(linha={"id": 1, "email": "ana@empresa.com"})
        cursor.fetchall.return_value = [{"id": 1, "nome": "Ana Costa"}]
        assert mysql_repo.buscar_por_email("ana@empresa.com", conexao=conexao)["id"] == 1
        assert mysql_repo.listar_usuarios(conexao=conexao) == [{"id": 1, "nome": "Ana Costa"}]
        assert all("senha_hash" not in sql for sql, _ in _sql_e_parametros(cursor))

    def test_atualiza_nivel_e_remove(self):
        conexao, cursor = _conexao_falsa()
        cursor.rowcount = 1
        assert mysql_repo.atualizar_nivel(3, 4, conexao=conexao) is True
        assert mysql_repo.remover_usuario(3, conexao=conexao) is True
        cursor.rowcount = 0
        assert mysql_repo.remover_usuario(99, conexao=conexao) is False
        assert all("%s" in sql for sql, _ in _sql_e_parametros(cursor))
        with pytest.raises(mysql_repo.NivelInvalidoError):
            mysql_repo.atualizar_nivel(3, 9, conexao=conexao)

    def test_conexao_que_cai_mostra_o_erro_real(self, monkeypatch):
        conexao = MagicMock()
        conexao.cursor.side_effect = mysql.connector.errors.OperationalError("MySQL server has gone away")
        monkeypatch.setattr(mysql_repo, "conectar", lambda: conexao)
        with pytest.raises(mysql.connector.Error):
            mysql_repo.autenticar("ana@empresa.com", "qualquer")
        conexao.close.assert_called_once()
