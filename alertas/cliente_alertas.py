"""Módulo 4b — Console de alertas: conecta ao servidor e recebe notificações em tempo real.

Uso: python -m alertas.cliente_alertas [host] [porta]
"""

import socket
import sys
import threading

HOST = "127.0.0.1"
PORTA = 9999


def receber_alertas(cliente):
    try:
        while dados := cliente.recv(4096).decode():
            print(dados, end="")
        print("\n[CLIENTE] Servidor desconectado.")
    except OSError:
        print("\n[CLIENTE] Conexao encerrada.")


def conectar_servidor(host=HOST, porta=PORTA):
    cliente = None
    try:
        cliente = socket.create_connection((host, porta), timeout=5)
        cliente.settimeout(None)
        print(f"[CLIENTE] Conectado ao servidor {host}:{porta}")
        print("Comandos: /status, /historico, /sair")
        threading.Thread(target=receber_alertas, args=(cliente,), daemon=True).start()

        while (comando := input("")) != "/sair":
            cliente.send(comando.encode())
        cliente.send(comando.encode())

    except ConnectionRefusedError:
        print("[CLIENTE] Servidor offline ou inacessivel.")
    except (OSError, EOFError, KeyboardInterrupt):
        print("[CLIENTE] Conexao perdida.")
    finally:
        if cliente is not None:
            cliente.close()
        print("[CLIENTE] Desconectado.")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    porta = int(sys.argv[2]) if len(sys.argv) > 2 else PORTA
    conectar_servidor(host, porta)
