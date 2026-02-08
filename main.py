#!/usr/bin/env python3
"""
Advanced Port Scanner - Main CLI Interface

Este é o arquivo principal que você executa para usar o scanner.
Ele junta todos os módulos e fornece uma interface de linha de comando amigável.

Uso:
    python main.py scanme.nmap.org              # Scan portas comuns
    python main.py 192.168.1.1 -p 1-1000        # Scan range de portas
    python main.py example.com -p 80,443,8080   # Scan portas específicas
    python main.py target.com --full            # Scan todas as portas (1-65535)
"""

import argparse
import sys
from colorama import Fore, Style, init
from tqdm import tqdm

# Importa nossos módulos personalizados
from scanner import PortScanner
from banner_grabber import BannerGrabber
from service_detector import ServiceDetector
from report_generator import ReportGenerator

# Inicializa colorama para cores no terminal
init(autoreset=True)

class PortScannerCLI:
    """Interface de linha de comando para o scanner"""
    
    def __init__(self):
        """Inicializa a CLI"""
        self.scanner = None
        self.grabber = BannerGrabber(timeout=2)
        self.detector = ServiceDetector()
        self.reporter = ReportGenerator()
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║                       HEFEST SCANNER                          ║
║                                                               ║
║                    By: Lukketes                               ║
║              GitHub: github.com/Lukketes/hefest               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def parse_ports(self, port_arg):
        """
        Converte argumento de portas em lista de portas
        
        Exemplos:
            "80" -> [80]
            "80,443,8080" -> [80, 443, 8080]
            "1-100" -> [1, 2, 3, ..., 100]
        
        Args:
            port_arg (str): Argumento de portas
            
        Returns:
            list: Lista de portas
        """
        if not port_arg:
            return None  # Vai usar portas comuns
        
        ports = []
        
        # Divide por vírgula (ex: 80,443,8080)
        parts = port_arg.split(',')
        
        for part in parts:
            # Verifica se é um range (ex: 1-1000)
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if start > end or start < 1 or end > 65535:
                        print(f"{Fore.RED}[!] Range inválido: {part}{Style.RESET_ALL}")
                        sys.exit(1)
                    ports.extend(range(start, end + 1))
                except ValueError:
                    print(f"{Fore.RED}[!] Range mal formatado: {part}{Style.RESET_ALL}")
                    sys.exit(1)
            else:
                # Porta única
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        print(f"{Fore.RED}[!] Porta inválida: {port}{Style.RESET_ALL}")
                        sys.exit(1)
                    ports.append(port)
                except ValueError:
                    print(f"{Fore.RED}[!] Porta inválida: {part}{Style.RESET_ALL}")
                    sys.exit(1)
        
        return sorted(list(set(ports)))  # Remove duplicatas e ordena
    
    def run_scan(self, target, ports=None, timeout=1, threads=100):
        """
        Executa o scan completo com todos os módulos
        
        Args:
            target (str): Alvo (IP ou hostname)
            ports (list): Lista de portas ou None para portas comuns
            timeout (int): Timeout de conexão
            threads (int): Número de threads
            
        Returns:
            dict: Resultados completos do scan
        """
        # Cria o scanner
        self.scanner = PortScanner(target, timeout, threads)
        
        # Se não especificou portas, usa as comuns
        if ports is None:
            ports = PortScanner.COMMON_PORTS
            print(f"{Fore.YELLOW}[*] Scanning common ports...{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[*] Scanning {len(ports)} ports...{Style.RESET_ALL}")
        
        # Progress bar com tqdm
        progress_bar = tqdm(total=len(ports), desc="Scanning", unit="port", 
                           bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} ports")
        
        def update_progress():
            """Callback para atualizar a barra de progresso"""
            progress_bar.update(1)
        
        # Executa o scan
        scan_results = self.scanner.scan(ports, progress_callback=update_progress)
        progress_bar.close()
        
        # Se encontrou portas abertas, faz banner grabbing e detecção de serviços
        if scan_results['open_ports']:
            print(f"\n{Fore.GREEN}[+] Found {len(scan_results['open_ports'])} open ports!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Performing service detection...{Style.RESET_ALL}")
            
            port_details = []
            
            for port in tqdm(scan_results['open_ports'], desc="Detecting services", unit="port"):
                # Identifica o serviço
                service_info = self.detector.identify_service(port)
                
                # Tenta capturar banner
                banner = self.grabber.grab_banner(target, port)
                
                # Se pegou banner, extrai informações extras
                if banner:
                    banner_info = BannerGrabber.extract_service_info(banner)
                    service_info['banner'] = banner
                    service_info['banner_service'] = banner_info.get('service')
                    service_info['version'] = banner_info.get('version')
                else:
                    service_info['banner'] = None
                
                # Adiciona nível de risco e recomendações
                service_info['risk_level'] = self.detector.get_risk_level(port)
                service_info['recommendations'] = self.detector.get_security_recommendations(port)
                
                port_details.append(service_info)
            
            # Adiciona detalhes ao resultado
            scan_results['port_details'] = port_details
        else:
            print(f"\n{Fore.RED}[!] No open ports found.{Style.RESET_ALL}")
            scan_results['port_details'] = []
        
        return scan_results
    
    def main(self):
        """Função principal da CLI"""
        # Parser de argumentos
        parser = argparse.ArgumentParser(
            description='Advanced Port Scanner - Professional network reconnaissance tool',
            epilog='Example: python main.py scanme.nmap.org -p 1-1000 -o report'
        )
        
        parser.add_argument('target', help='Target IP address or hostname')
        parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 80,443 or 1-1000)')
        parser.add_argument('--full', action='store_true', help='Scan all ports (1-65535)')
        parser.add_argument('-t', '--timeout', type=int, default=1, help='Connection timeout (default: 1s)')
        parser.add_argument('--threads', type=int, default=100, help='Number of threads (default: 100)')
        parser.add_argument('-o', '--output', help='Output filename (without extension)')
        parser.add_argument('--format', choices=['json', 'csv', 'txt', 'all'], default='all',
                          help='Report format (default: all)')
        parser.add_argument('--no-banner', action='store_true', help='Disable banner display')
        
        args = parser.parse_args()
        
        # Mostra banner
        if not args.no_banner:
            self.print_banner()
        
        # Processa portas
        if args.full:
            ports = list(range(1, 65536))
            print(f"{Fore.RED}[!] WARNING: Full port scan (65535 ports) will take a long time!{Style.RESET_ALL}")
        else:
            ports = self.parse_ports(args.ports)
        
        # Executa o scan
        try:
            print(f"\n{Fore.CYAN}[*] Target: {args.target}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Timeout: {args.timeout}s | Threads: {args.threads}{Style.RESET_ALL}")
            print()
            
            results = self.run_scan(args.target, ports, args.timeout, args.threads)
            
            # Mostra resumo no terminal
            summary = self.reporter.generate_summary(results)
            print(summary)
            
            # Gera relatórios se solicitado
            if args.output:
                print(f"\n{Fore.YELLOW}[*] Generating reports...{Style.RESET_ALL}")
                
                if args.format == 'all':
                    files = self.reporter.generate_all(results, args.output)
                    print(f"{Fore.GREEN}[+] Reports generated:{Style.RESET_ALL}")
                    for fmt, filepath in files.items():
                        if filepath:
                            print(f"    - {filepath}")
                else:
                    # Gera formato específico
                    if args.format == 'json':
                        filepath = self.reporter.generate_json(results, f"{args.output}.json")
                    elif args.format == 'csv':
                        filepath = self.reporter.generate_csv(results, f"{args.output}.csv")
                    else:  # txt
                        filepath = self.reporter.generate_text(results, f"{args.output}.txt")
                    
                    print(f"{Fore.GREEN}[+] Report saved: {filepath}{Style.RESET_ALL}")
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
            sys.exit(1)

# Ponto de entrada do programa
if __name__ == '__main__':
    cli = PortScannerCLI()
    cli.main()