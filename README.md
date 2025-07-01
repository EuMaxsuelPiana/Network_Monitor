# 🔐 Network Monitor

Script de Monitoramento de Rede e Portas Abertas para Linux e Windows, com alertas visuais, log detalhado e varredura contínua ou pontual.

---

## 📌 Descrição

Este script monitora conexões de rede ativas no sistema operacional, verifica se alguma porta suspeita está sendo utilizada e alerta o usuário de forma visual e por log.

Você pode rodar ele de forma pontual (varredura única) ou em modo contínuo, verificando a rede em intervalos configuráveis.

---

## ⚙️ Funcionalidades

- ✅ Compatível com Linux e Windows
- ✅ Verifica conexões usando `netstat`, `ss`, `lsof`
- ✅ Lista de portas autorizadas personalizável (`suspicious_ports.txt`)
- ✅ Alerta visual ao detectar uma porta suspeita
- ✅ Cria um log detalhado com data/hora
- ✅ Modo contínuo com intervalo ajustável
- ✅ Notificações via `notify-send`, `win10toast` ou fallback com `ctypes` no Windows

---

## 🖥️ Clone o repositório :
```bash
git clone https://github.com/EuMaxsuelPiana/Network_Monitor.git
cd Network_Monitor
python3 network_monitor.py

### Linux:
```bash
sudo apt install net-tools lsof libnotify-bin
