# 🔍 Hefest Port Scanner

Um scanner de portas profissional e completo desenvolvido em Python para reconhecimento de rede e testes de penetração.

## ✨ Funcionalidades

- ✅ **Scan Multi-threaded**: Utiliza threads paralelas para scans rápidos
- ✅ **Banner Grabbing**: Captura informações dos serviços rodando nas portas
- ✅ **Service Detection**: Identifica serviços automaticamente
- ✅ **Risk Assessment**: Avalia o nível de risco de cada porta exposta
- ✅ **Multiple Report Formats**: Exporta em JSON, CSV e TXT
- ✅ **Security Recommendations**: Fornece dicas de segurança para cada serviço
- ✅ **Beautiful CLI**: Interface colorida e progress bars

## 📋 Requisitos

- Python 3.8 ou superior
- Bibliotecas: `colorama`, `tqdm`

## 🚀 Instalação

```bash
# Clone o repositório
git clone https://github.com/Lukketes/hefest-portscanner
cd hefest-portscanner

# Crie um ambiente virtual (recomendado)
python -m venv venv

# Ative o ambiente virtual
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Instale as dependências
pip install -r requiriments.txt
```

## 💻 Uso

### Scan Básico (portas comuns)
```bash
python main.py scanme.nmap.org
```

### Scan de Range de Portas
```bash
python main.py 192.168.1.1 -p 1-1000
```

### Scan de Portas Específicas
```bash
python main.py example.com -p 80,443,8080,3306
```

### Scan Completo (todas as 65535 portas)
```bash
python main.py target.com --full
```

### Gerando Relatórios
```bash
# Gera todos os formatos
python main.py target.com -o resultado

# Gera apenas JSON
python main.py target.com -o resultado --format json
```

### Opções Avançadas
```bash
python main.py target.com -p 1-5000 --timeout 2 --threads 200 -o scan_report
```

## 📊 Exemplos de Output

### Terminal
```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║                      HEFEST SCANNER                           ║
║                      By: Lukketes                             ║
║              GitHub: github.com/Lukketes/hefest               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

[*] Target: scanme.nmap.org
[*] Timeout: 1s | Threads: 100

Scanning: 100%|████████████████████| 22/22 ports

[+] Found 3 open ports!

SCAN SUMMARY
============================================================
Target: scanme.nmap.org (45.33.32.156)
Duration: 2.34s
Ports Scanned: 22
Open Ports: 3

Open Ports:
  🟢 Port 22: SSH [LOW RISK]
  🟢 Port 80: HTTP [LOW RISK]
  🟢 Port 443: HTTPS [LOW RISK]
============================================================
```

### Relatório JSON
```json
{
    "generated_at": "2025-12-14T10:30:00",
    "scan_data": {
        "target": "scanme.nmap.org",
        "target_ip": "45.33.32.156",
        "duration": 2.34,
        "open_ports": [22, 80, 443],
        "port_details": [...]
    }
}
```

## 🏗️ Arquitetura

```
hefest/
├── scanner.py          # Core do scanner (threading, conexões)
├── banner_grabber.py   # Captura de banners dos serviços
├── service_detector.py # Detecção e categorização de serviços
├── report_generator.py # Geração de relatórios (JSON, CSV, TXT)
├── main.py            # Interface CLI principal
├── requirements.txt   # Dependências
└── README.md         # Esta documentação
```

## 🔒 Aviso Legal

**⚠️ IMPORTANTE**: Este scanner foi desenvolvido apenas para fins educacionais e testes de segurança autorizados.

- ✅ **USE**: Em suas próprias redes e sistemas
- ✅ **USE**: Com permissão explícita por escrito do proprietário
- ✅ **USE**: Em ambientes de teste como scanme.nmap.org
- ❌ **NÃO USE**: Contra sistemas sem autorização
- ❌ **NÃO USE**: Para atividades ilegais

O autor não se responsabiliza pelo uso indevido desta ferramenta. O uso não autorizado de scanners de porta pode ser ilegal em muitas jurisdições.

## 🎓 Conceitos Aprendidos

Este projeto demonstra conhecimento em:

- **Programação de Sockets**: TCP connections, timeouts, error handling
- **Threading**: Concurrent execution, thread safety, queues
- **Network Protocols**: HTTP, HTTPS, SSH, FTP, SMTP, etc
- **Security Concepts**: Port scanning, banner grabbing, service detection
- **Python Best Practices**: Modularização, POO, documentação
- **CLI Development**: argparse, colorama, progress bars

**Seu Nome**
- GitHub: [@Lukketes](https://github.com/Lukketes)
- LinkedIn: [Lucas Freitas](https://www.linkedin.com/in/lucas-freitas-592180329/)

**Para Recrutadores**: Este projeto demonstra conhecimento prático em Python, networking, threading, e conceitos fundamentais de cybersecurity ofensiva.
