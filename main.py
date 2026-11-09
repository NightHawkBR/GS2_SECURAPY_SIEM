"""SecuraPy Platform — linha de comando.

  python main.py analisar [--sem-banco] [--sem-tempo-real] [--saida ARQ]
  python main.py ingerir            carga inicial dos logs e da geolocalização no MongoDB
  python main.py treinar            treina o modelo de risco
  python main.py operador           cadastra um operador no MySQL
  python main.py api                API + dashboard (desenvolvimento)
  python main.py alertas            servidor TCP de alertas
  python main.py console [host] [porta]
  python main.py menu               menu interativo do 1º semestre
"""

import argparse
import getpass
import logging
import sys

from config import settings
from core import relatorios
from core.enriquecimento import carregar_cache, enriquecer_alertas, salvar_cache

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass


def cmd_analisar(args):
    from orquestrador import executar_analise

    resultado = executar_analise(persistir=not args.sem_banco, transmitir=not args.sem_tempo_real)
    resumo = resultado["resumo"]
    print(f"\n[OK] {resumo['total_eventos']} eventos · {resumo['total_alertas']} alertas · "
          f"{resumo['total_ameacas']} ameaças")
    for etapa, status in resumo["etapas"].items():
        print(f"     {etapa:<15} {status}")
    print(f"     IPs anômalos (Isolation Forest): {', '.join(resumo['ips_anomalos']) or 'nenhum'}")

    geo = {a["ip"]: a["geolocalizacao"] for a in resultado["alertas"] if a.get("geolocalizacao")}
    dados = relatorios.montar_dados_relatorio(resultado["eventos"], resultado["alertas"], geo, resultado["ameacas"])
    relatorios.exportar_relatorio_json(dados, args.saida or relatorios.gerar_nome_relatorio(settings.PASTA_SAIDA))


def cmd_ingerir(_):
    from db.migracao import migrar, semear_geolocalizacao
    print(f"[OK] {migrar()} eventos persistidos no MongoDB.")
    print(f"[OK] {semear_geolocalizacao()} geolocalizações iniciais gravadas.")


def cmd_treinar(_):
    from ml.treinar import exibir_relatorio, treinar_e_salvar
    exibir_relatorio(treinar_e_salvar())


def cmd_operador(_):
    from db import mysql_repo
    nome = input("Nome: ").strip()
    email = input("Email: ").strip()
    nivel = int(input("Nível (1-5): ") or 1)
    senha = getpass.getpass("Senha: ")
    try:
        print(f"[OK] Operador criado com id {mysql_repo.criar_usuario(nome, email, senha, nivel)}.")
    except mysql_repo.EmailDuplicadoError:
        print("[ERRO] Email já cadastrado.")
    except mysql_repo.NivelInvalidoError:
        print("[ERRO] Nível deve estar entre 1 e 5.")


def cmd_api(_):
    from api.app import criar_app
    criar_app().run(host="0.0.0.0", port=5000, debug=False)


def cmd_alertas(_):
    from alertas.servidor_alertas import iniciar_servidor
    iniciar_servidor(settings.ALERTAS_HOST, settings.ALERTAS_PORTA)


def cmd_console(args):
    from alertas.cliente_alertas import conectar_servidor
    conectar_servidor(args.host, args.porta)


def cmd_menu(_):
    """Menu clássico do 1º semestre, agora sobre o núcleo reorganizado."""
    from core.pipeline import analisar_pasta

    resultado = {"eventos": [], "alertas": [], "ameacas": []}
    cache = carregar_cache(settings.ARQUIVO_CACHE_GEO)

    while (opcao := relatorios.exibir_menu()) != 0:
        eventos, alertas = resultado["eventos"], resultado["alertas"]
        match opcao:
            case 1:
                resultado = analisar_pasta(
                    settings.PASTA_LOGS, settings.ARQUIVO_REGRAS, settings.BLACKLIST,
                    janela_segundos=settings.BRUTE_FORCE_JANELA_SEGUNDOS,
                    limite_rajada=settings.BRUTE_FORCE_LIMITE_JANELA,
                )
                print(f"\n[OK] {len(resultado['eventos'])} eventos · {len(resultado['alertas'])} alertas · "
                      f"{len(resultado['ameacas'])} ameaças.")
            case 2:
                relatorios.resumo_geral(eventos, alertas)
            case 3:
                filtros = {campo: input(f"{campo.capitalize()}: ").strip() or None for campo in ("fonte", "tipo", "ip")}
                achados = relatorios.filtrar_eventos(eventos, **filtros)
                print(f"\n[OK] {len(achados)} evento(s).")
                relatorios.exibir_tabela(achados[:50], ["timestamp", "fonte", "tipo", "ip", "detalhes"])
            case 4:
                if ip := input("\nDigite o IP: ").strip():
                    relatorios.buscar_ip(ip, eventos, alertas, cache)
            case 5:
                relatorios.exibir_top_ips(eventos, alertas)
            case 6:
                relatorios.exibir_alertas_por_severidade(alertas)
            case 7:
                enriquecer_alertas(alertas, cache)
                salvar_cache(cache, settings.ARQUIVO_CACHE_GEO)
                print(f"[OK] Cache com {len(cache)} IP(s).")
            case 8:
                dados = relatorios.montar_dados_relatorio(eventos, alertas, cache, resultado["ameacas"])
                relatorios.exportar_relatorio_json(dados, relatorios.gerar_nome_relatorio(settings.PASTA_SAIDA))
            case 9:
                cmd_alertas(None)
    print("\nEncerrando SecuraPy. Ate logo!")


def _parser():
    parser = argparse.ArgumentParser(prog="securapy", description="SecuraPy Platform — SIEM")
    sub = parser.add_subparsers(dest="comando", required=True)

    analisar = sub.add_parser("analisar", help="núcleo + ML + persistência + relatório JSON")
    analisar.add_argument("--sem-banco", action="store_true")
    analisar.add_argument("--sem-tempo-real", action="store_true")
    analisar.add_argument("--saida", help="caminho do relatório JSON")
    analisar.set_defaults(func=cmd_analisar)

    console = sub.add_parser("console", help="console de alertas em tempo real")
    console.add_argument("host", nargs="?", default="127.0.0.1")
    console.add_argument("porta", nargs="?", type=int, default=settings.ALERTAS_PORTA)
    console.set_defaults(func=cmd_console)

    for nome, func, ajuda in (
        ("ingerir", cmd_ingerir, "carga inicial no MongoDB"),
        ("treinar", cmd_treinar, "treina e salva o modelo de risco"),
        ("operador", cmd_operador, "cadastra operador no MySQL"),
        ("api", cmd_api, "API + dashboard (desenvolvimento)"),
        ("alertas", cmd_alertas, "servidor TCP de alertas"),
        ("menu", cmd_menu, "menu interativo do 1º semestre"),
    ):
        sub.add_parser(nome, help=ajuda).set_defaults(func=func)
    return parser


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    args = _parser().parse_args(argv)
    try:
        args.func(args)
    except NotImplementedError:
        print(f"[PENDENTE] '{args.comando}' depende de um módulo ainda não implementado — veja o README.")
    except KeyboardInterrupt:
        print("\n[OK] Encerrado.")


if __name__ == "__main__":
    main()
