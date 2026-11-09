"""Módulo 4a — Servidor TCP de alertas em tempo real (broadcast para os consoles conectados).

Comandos do console: /status · /historico · /sair
"""

import os
import socket
import threading

HOST = os.environ.get("ALERTAS_HOST", "0.0.0.0")
PORTA = int(os.environ.get("ALERTAS_PORTA", "9999"))
MAX_CLIENTES = 10
TAMANHO_HISTORICO = 10

clientes = {}                  # {conexao: endereco}
lock = threading.Lock()
historico_alertas = []
_no_ar = threading.Event()     # ligado só enquanto a porta está escutando


def esta_no_ar():
    return _no_ar.is_set()


def formatar_alerta(alerta):
    hora = alerta["timestamp"].split(" ")[-1]
    return (f"[{hora}] [{alerta['severidade']}] {alerta['regra_nome']} - "
            f"{alerta['ip']} - {alerta['descricao']}")


def _enviar(conexao, texto):
    conexao.send(f"{texto}\n".encode())


def broadcast_alerta(alerta):
    mensagem = formatar_alerta(alerta) if isinstance(alerta, dict) else alerta

    with lock:
        historico_alertas.append(mensagem)
        destinos = list(clientes)

    for conexao in destinos:
        try:
            _enviar(conexao, mensagem)
        except OSError:
            remover_cliente(conexao)


def remover_cliente(conexao):
    with lock:
        endereco = clientes.pop(conexao, None)
    if endereco:
        print(f"[SERVIDOR] Cliente {endereco} desconectado")
    try:
        conexao.close()
    except OSError:
        pass


def _responder(conexao, comando):
    match comando:
        case "/status":
            _enviar(conexao, f"Clientes conectados: {len(clientes)} | "
                             f"Alertas na sessao: {len(historico_alertas)}")
        case "/historico":
            recentes = historico_alertas[-TAMANHO_HISTORICO:] or ["Nenhum alerta registrado."]
            for linha in recentes:
                _enviar(conexao, linha)
        case _:
            _enviar(conexao, "Comando invalido. Use /status, /historico ou /sair.")


def tratar_cliente(conexao, endereco):
    with lock:
        clientes[conexao] = endereco
    try:
        _enviar(conexao, "Conectado ao servidor de alertas!")
        while dados := conexao.recv(1024).decode():
            comando = dados.strip()
            if comando == "/sair":
                break
            _responder(conexao, comando)
    except OSError:
        pass
    finally:
        remover_cliente(conexao)


def iniciar_servidor(host=HOST, porta=PORTA):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        servidor.bind((host, porta))
    except OSError as erro:
        servidor.close()
        print(f"[SERVIDOR] Porta {porta} indisponivel ({erro.strerror}) - alertas em tempo real desativados")
        return
    servidor.listen(MAX_CLIENTES)
    _no_ar.set()
    print(f"[SERVIDOR] Aguardando conexoes em {host}:{porta}...")

    try:
        while True:
            conexao, endereco = servidor.accept()
            print(f"[SERVIDOR] Nova conexao de {endereco}")
            threading.Thread(target=tratar_cliente, args=(conexao, endereco), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[SERVIDOR] Encerrando...")
    finally:
        _no_ar.clear()
        servidor.close()


def iniciar_em_background(host=HOST, porta=PORTA):
    """Sobe o servidor numa thread daemon — usado pela API dentro do contêiner."""
    thread = threading.Thread(target=iniciar_servidor, args=(host, porta), daemon=True, name="alertas-tcp")
    thread.start()
    return thread


if __name__ == "__main__":
    iniciar_servidor()
