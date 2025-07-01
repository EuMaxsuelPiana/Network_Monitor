import os
import platform
import re
import subprocess
import time
from datetime import datetime

# --- Configurações --- #

# Nome do arquivo de log.
ARQUIVO_LOG = "network_monitor.log"

# Nome do arquivo de configuração para portas suspeitas.
ARQUIVO_PORTAS_SUSPEITAS = "suspicious_ports.txt"

# Lista de portas conhecidas/autorizadas. Conexões em outras portas serão consideradas suspeitas.
# Esta lista será carregada do arquivo ARQUIVO_PORTAS_SUSPEITAS, se existir.
PORTAS_AUTORIZADAS = {
    80,    # HTTP
    443,   # HTTPS
    22,    # SSH
    25,    # SMTP
    53,    # DNS
    123,   # NTP
    # Adicione outras portas que são consideradas seguras no seu ambiente.
}

# Intervalo em segundos para o modo de monitoramento contínuo.
INTERVALO_CONTINUO = 60

# --- Funções de Detecção de SO e Notificação --- #

def get_so():
    """Identifica o sistema operacional."""
    return platform.system().lower()

def notificar(titulo, mensagem, so):
    """Envia uma notificação visual para o usuário."""
    print(f"\n--- ALERTA ---\n{titulo}: {mensagem}\n--------------\n")
    try:
        if so == "linux":
            # Tenta usar notify-send
            subprocess.run(["notify-send", titulo, mensagem], check=True)
        elif so == "windows":
            # Tenta usar win10toast (se instalado) ou ctypes como fallback
            try:
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast(titulo, mensagem, duration=10)
            except ImportError:
                print("(Nota: Para melhores notificações no Windows, instale 'win10toast-py3': pip install win10toast-py3)")
                ctypes.windll.user32.MessageBoxW(0, mensagem, titulo, 0x40)
    except (FileNotFoundError, subprocess.CalledProcessError, ImportError) as e:
        print(f"[AVISO] Não foi possível enviar notificação visual: {e}")
        print("O alerta será exibido apenas no terminal.")

# --- Funções de Coleta de Dados --- #

def executar_comando(comando):
    """Executa um comando no shell e retorna a saída."""
    try:
        resultado = subprocess.run(comando, shell=True, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore')
        return resultado.stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log(f"Erro ao executar o comando '{comando}': {e}", "ERROR")
        return ""

def coletar_conexoes_linux():
    """Coleta informações de rede no Linux usando netstat, ss e lsof."""
    conexoes = ""
    # netstat: -anp mostra todas as conexões, portas e processos
    conexoes += executar_comando("netstat -anp")
    # ss: -tuln mostra sockets TCP/UDP abertos
    conexoes += executar_comando("ss -tuln")
    # lsof: -i lista arquivos abertos por processos de rede
    conexoes += executar_comando("lsof -i")
    return conexoes

def coletar_conexoes_windows():
    """Coleta informações de rede no Windows usando netstat."""
    # netstat: -ano mostra todas as conexões, portas e o PID do processo
    return executar_comando("netstat -ano")

# --- Funções de Análise e Log --- #

def log(mensagem, nivel="INFO"):
    """Registra uma mensagem no arquivo de log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ARQUIVO_LOG, "a", encoding='utf-8') as f:
        f.write(f"[{timestamp}] [{nivel}] {mensagem}\n")

def carregar_portas_autorizadas(caminho_arquivo):
    """Carrega portas autorizadas de um arquivo externo."""
    portas = set()
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as f:
            for linha in f:
                linha = linha.strip()
                if linha and not linha.startswith('#'):
                    try:
                        portas.add(int(linha))
                    except ValueError:
                        log(f"Linha inválida no arquivo de portas: {linha}", "WARNING")
        log(f"Portas autorizadas carregadas de {caminho_arquivo}. Total: {len(portas)}.")
    except FileNotFoundError:
        log(f"Arquivo de portas autorizadas não encontrado: {caminho_arquivo}. Usando portas padrão.", "WARNING")
    except Exception as e:
        log(f"Erro ao carregar portas autorizadas de {caminho_arquivo}: {e}", "ERROR")
    return portas

def analisar_conexoes(conexoes, so):
    """Analisa as conexões em busca de portas suspeitas."""
    log("Iniciando análise de conexões.")
    portas_suspeitas_encontradas = set()

    # Carrega as portas autorizadas do arquivo (se existir) e as combina com as portas padrão.
    # Isso permite que o usuário adicione portas à lista padrão.
    portas_autorizadas_custom = carregar_portas_autorizadas(ARQUIVO_PORTAS_SUSPEITAS)
    todas_portas_autorizadas = PORTAS_AUTORIZADAS.union(portas_autorizadas_custom)

    # Regex para encontrar endereços locais com portas (ex: 127.0.0.1:8080, *:5500)
    # Captura o número da porta
    regex_porta = re.compile(r":(\d{2,5})\s")

    for linha in conexoes.splitlines():
        match = regex_porta.search(linha)
        if match:
            porta = int(match.group(1))
            if porta not in todas_portas_autorizadas and porta not in portas_suspeitas_encontradas:
                mensagem = f"Detectada conexão suspeita na porta {porta}. Linha: {linha.strip()}"
                log(mensagem, "WARNING")
                notificar("Porta Suspeita Detectada", f"Conexão na porta {porta} pode ser um risco.", so)
                portas_suspeitas_encontradas.add(porta)

    if not portas_suspeitas_encontradas:
        log("Nenhuma porta suspeita encontrada nesta varredura.")
        print("Nenhuma porta suspeita encontrada.")
    else:
        print(f"Análise concluída. {len(portas_suspeitas_encontradas)} porta(s) suspeita(s) detectada(s). Verifique o log para detalhes.")

# --- Funções Principais e Menu --- #

def rodar_varredura_unica(so):
    """Executa uma única varredura completa do sistema."""
    print("\nIniciando varredura única...")
    log("Varredura única iniciada pelo usuário.")
    if so == "linux":
        conexoes = coletar_conexoes_linux()
    elif so == "windows":
        conexoes = coletar_conexoes_windows()
    else:
        print(f"Sistema operacional '{so}' não suportado.")
        log(f"Tentativa de execução em SO não suportado: {so}", "ERROR")
        return

    if conexoes:
        analisar_conexoes(conexoes, so)
    else:
        print("Não foi possível coletar dados de rede.")
        log("Falha na coleta de dados de rede.", "ERROR")

def ativar_modo_continuo(so):
    """Ativa o monitoramento contínuo em intervalos definidos."""
    print(f"\nAtivando modo de monitoramento contínuo (intervalo: {INTERVALO_CONTINUO}s).")
    print("Pressione Ctrl+C para parar.")
    log("Modo de monitoramento contínuo ativado.")
    try:
        while True:
            rodar_varredura_unica(so)
            time.sleep(INTERVALO_CONTINUO)
    except KeyboardInterrupt:
        print("\nMonitoramento contínuo interrompido pelo usuário.")
        log("Monitoramento contínuo interrompido.")

def imprimir_cabecalho():
    """Imprime o cabeçalho e as instruções iniciais."""
    print("="*60)
    print("      SCRIPT DE MONITORAMENTO DE REDE E PORTAS ABERTAS")
    print("="*60)
    print("Este script irá verificar as conexões de rede ativas e alertar")
    print("sobre qualquer porta aberta que não esteja na lista de portas")
    print("autorizadas, definida no script e/ou no arquivo ")
    print(f"'{ARQUIVO_PORTAS_SUSPEITAS}'.")
    print("\nDependências (Linux): 'net-tools', 'lsof', 'libnotify-bin'")
    print("  (sudo apt install net-tools lsof libnotify-bin)")
    print("Dependências (Windows): 'win10toast-py3'")
    print("  (pip install win10toast-py3)")
    print("-"*60)

def menu():
    """Exibe o menu principal e gerencia a interação com o usuário."""
    so = get_so()
    imprimir_cabecalho()
    log(f"Script iniciado. SO detectado: {so}.", "INFO")

    while True:
        print("\nEscolha uma opção:")
        print("  1. Rodar varredura única")
        print("  2. Ativar modo de monitoramento contínuo")
        print("  3. Sair")
        
        escolha = input("Opção: ")

        if escolha == '1':
            rodar_varredura_unica(so)
        elif escolha == '2':
            ativar_modo_continuo(so)
        elif escolha == '3':
            print("Saindo...")
            log("Script finalizado pelo usuário.")
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    try:
        menu()
    except Exception as e:
        log(f"Ocorreu um erro inesperado: {e}", "CRITICAL")
        print(f"\n[ERRO CRÍTICO] Ocorreu um erro inesperado: {e}")
        print("Verifique o arquivo de log para mais detalhes.")


