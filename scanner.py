"""
Port Scanner em Python
----------------------
Scanner de portas TCP simples, feito para estudo de reconhecimento de rede
(primeira etapa de um teste de invasão).

AVISO: use apenas em máquinas suas ou em alvos com autorização explícita,
como o host de testes oficial do Nmap: scanme.nmap.org.
"""

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Serviços mais comuns por porta (para deixar o resultado mais legível)
SERVICOS_COMUNS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 27017: "MongoDB",
}


def interpretar_portas(texto):
    """Converte '22,80,100-110' em uma lista de inteiros."""
    portas = set()
    for parte in texto.split(","):
        parte = parte.strip()
        if "-" in parte:
            inicio, fim = parte.split("-")
            portas.update(range(int(inicio), int(fim) + 1))
        elif parte:
            portas.add(int(parte))
    validas = sorted(p for p in portas if 1 <= p <= 65535)
    if not validas:
        raise ValueError("Nenhuma porta válida informada (use 1 a 65535).")
    return validas


def capturar_banner(sock):
    """Tenta ler a mensagem de apresentação do serviço (banner grabbing)."""
    try:
        sock.settimeout(1)
        dados = sock.recv(1024)
        return dados.decode(errors="ignore").strip().splitlines()[0][:60]
    except (socket.timeout, OSError, IndexError):
        return ""


def verificar_porta(ip, porta, timeout):
    """Retorna (porta, banner) se a porta estiver aberta, senão None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((ip, porta)) == 0:
            return porta, capturar_banner(sock)
    return None


def main():
    parser = argparse.ArgumentParser(description="Scanner de portas TCP para estudo.")
    parser.add_argument("alvo", help="IP ou domínio (ex.: scanme.nmap.org)")
    parser.add_argument("-p", "--portas", default="1-1024",
                        help="Portas: '80', '22,80,443' ou '1-1024' (padrão: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=0.5,
                        help="Tempo de espera por porta, em segundos (padrão: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="Número de threads simultâneas (padrão: 100)")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.alvo)
        portas = interpretar_portas(args.portas)
    except socket.gaierror:
        print(f"[!] Não foi possível resolver o endereço: {args.alvo}")
        return
    except ValueError as erro:
        print(f"[!] {erro}")
        return

    print(f"[*] Alvo: {args.alvo} ({ip})")
    print(f"[*] Portas: {len(portas)} | Início: {datetime.now():%H:%M:%S}")
    print("-" * 55)

    abertas = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        resultados = executor.map(lambda p: verificar_porta(ip, p, args.timeout), portas)
        for resultado in resultados:
            if resultado:
                porta, banner = resultado
                servico = SERVICOS_COMUNS.get(porta, "desconhecido")
                abertas.append(porta)
                linha = f"[+] {porta:>5}/tcp  aberta  {servico}"
                print(linha + (f"  | {banner}" if banner else ""))

    print("-" * 55)
    print(f"[*] {len(abertas)} porta(s) aberta(s) | Fim: {datetime.now():%H:%M:%S}")


if __name__ == "__main__":
    main()
