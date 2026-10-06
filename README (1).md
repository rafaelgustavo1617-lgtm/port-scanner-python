# 🔍 Port Scanner em Python

Scanner de portas TCP desenvolvido para estudo de **reconhecimento de rede**, a primeira etapa de um teste de invasão (pentest).

> ⚠️ **Uso ético:** escaneie apenas máquinas suas ou alvos com autorização explícita. Para testar, use o host oficial do Nmap: `scanme.nmap.org`.

## Funcionalidades
- Varredura de portas TCP individuais, listas ou intervalos (`22,80,443` ou `1-1024`)
- Varredura paralela com threads (rápida)
- Identificação dos serviços mais comuns (SSH, HTTP, MySQL...)
- Captura de banner (*banner grabbing*) para identificar o software do serviço
- Tratamento de erros (domínio inválido, portas inválidas)

## Tecnologias
- Python 3 (somente bibliotecas padrão: `socket`, `argparse`, `concurrent.futures`)

## Como usar
```bash
git clone https://github.com/rafaelgustavo1617-lgtm/port-scanner-python.git
cd port-scanner-python

# portas 1 a 1024 (padrão)
python scanner.py scanme.nmap.org

# portas específicas
python scanner.py scanme.nmap.org -p 22,80,443

# ajustar tempo de espera e número de threads
python scanner.py 192.168.0.1 -p 1-500 -t 1 -w 50
```

## Exemplo de saída
```
[*] Alvo: scanme.nmap.org (45.33.32.156)
[*] Portas: 1024 | Início: 20:30:12
-------------------------------------------------------
[+]    22/tcp  aberta  SSH  | SSH-2.0-OpenSSH_6.6.1p1 Ubuntu
[+]    80/tcp  aberta  HTTP
-------------------------------------------------------
[*] 2 porta(s) aberta(s) | Fim: 20:30:18
```

## O que aprendi
- Como funciona o *three-way handshake* TCP e por que uma conexão aceita indica porta aberta
- Programação com sockets e concorrência em Python
- O papel do reconhecimento na metodologia de pentest

## Próximos passos
- [ ] Varredura UDP
- [ ] Exportar resultado em JSON/CSV
- [ ] Comparar resultados com o Nmap

---
Desenvolvido por **Rafael Gustavo de França Lima** · Estudante de Engenharia de Software
