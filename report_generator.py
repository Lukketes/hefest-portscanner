"""
Report Generator Module

Este módulo gera relatórios dos scans em diferentes formatos:
- JSON: Para processamento automático e APIs
- TXT: Relatório legível para humanos
"""

import os
import json
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        """Inicializa o gerador de relatórios"""
        # Define o diretório de resultados
        self.results_dir = 'results'
        
        # Cria a pasta results se não existir
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
    
    def generate_json(self, scan_results, filename='scan_report.json'):
        """
        Gera relatório em formato JSON
        
        JSON é ótimo para:
        - Integração com outras ferramentas
        - Processamento automático
        - APIs e pipelines de CI/CD
        
        Args:
            scan_results (dict): Resultados do scan
            filename (str): Nome do arquivo de saída
            
        Returns:
            str: Caminho do arquivo gerado
        """
        try:
            # Monta o caminho completo do arquivo
            filepath = os.path.join(self.results_dir, filename)
            
            # Adiciona timestamp ao relatório
            report = {
                'generated_at': datetime.now().isoformat(),
                'scan_data': scan_results
            }
            
            # Salva com indentação bonita (pretty print)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4, ensure_ascii=False)
            
            return filepath
            
        except Exception as e:
            print(f"Erro ao gerar JSON: {e}")
            return None
    
    def generate_text(self, scan_results, filename='scan_report.txt'):
        """
        Gera relatório em formato texto legível
        
        TXT é ótimo para:
        - Leitura humana
        - Compartilhamento rápido
        - Documentação
        
        Args:
            scan_results (dict): Resultados do scan
            filename (str): Nome do arquivo de saída
            
        Returns:
            str: Caminho do arquivo gerado
        """
        try:
            # Monta o caminho completo do arquivo
            filepath = os.path.join(self.results_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                # Cabeçalho do relatório
                f.write("="*70 + "\n")
                f.write("HefestPortsScan\n".center(70))
                f.write("="*70 + "\n\n")
                
                # Informações gerais
                f.write(f"Alvo: {scan_results.get('target', 'N/A')}\n")
                f.write(f"Endereço IP: {scan_results.get('target_ip', 'N/A')}\n")
                f.write(f"Tempo de Scan: {scan_results.get('scan_time', 'N/A')}\n")
                f.write(f"Duração: {scan_results.get('duration', 0):.2f} seconds\n")
                f.write(f"Portas Scanneadas: {scan_results.get('ports_scanned', 0)}\n")
                f.write(f"Portas abertas encontradas: {scan_results.get('total_open', 0)}\n")
                f.write("\n" + "="*70 + "\n\n")
                
                # Detalhes das portas abertas
                if scan_results.get('total_open', 0) > 0:
                    f.write("OPEN PORTS DETAILS:\n")
                    f.write("-"*70 + "\n\n")
                    
                    if 'port_details' in scan_results:
                        for port_info in scan_results['port_details']:
                            f.write(f"Port: {port_info.get('port')}\n")
                            f.write(f"  Service: {port_info.get('service', 'Unknown')}\n")
                            f.write(f"  Description: {port_info.get('description', 'N/A')}\n")
                            f.write(f"  Protocol: {port_info.get('protocol', 'TCP')}\n")
                            f.write(f"  Category: {port_info.get('category', 'unknown')}\n")
                            f.write(f"  Risk Level: {port_info.get('risk_level', 'UNKNOWN')}\n")
                            
                            # Banner se disponível
                            if port_info.get('banner'):
                                f.write(f"  Banner: {port_info['banner'][:100]}...\n")
                            
                            # Recomendações de segurança
                            if port_info.get('recommendations'):
                                f.write("  Security Recommendations:\n")
                                for rec in port_info['recommendations']:
                                    f.write(f"    - {rec}\n")
                            
                            f.write("\n" + "-"*70 + "\n\n")
                else:
                    f.write("No open ports found.\n")
                
                # Rodapé
                f.write("\n" + "="*70 + "\n")
                f.write("End of Report\n")
                f.write("="*70 + "\n")
            
            return filepath
            
        except Exception as e:
            print(f"Erro ao gerar TXT: {e}")
            return None
    
    def generate_summary(self, scan_results):
        """
        Gera um resumo rápido dos resultados (para exibir no terminal)
        
        Args:
            scan_results (dict): Resultados do scan
            
        Returns:
            str: String formatada com o resumo
        """
        summary = []
        summary.append("\n" + "="*70)
        summary.append("SUMÁRIO DO SCAN".center(70))
        summary.append("="*70)
        summary.append(f"\nAlvo: {scan_results.get('target')} ({scan_results.get('target_ip')})")
        summary.append(f"Duração: {scan_results.get('duration', 0):.2f}s")
        summary.append(f"Portas Scaneadas: {scan_results.get('ports_scanned', 0)}")
        summary.append(f"Portas Abertas: {scan_results.get('total_open', 0)}")
        
        if scan_results.get('total_open', 0) > 0:
            summary.append("\nPortas Abertas:")
            if 'port_details' in scan_results:
                for port_info in scan_results['port_details']:
                    risk = port_info.get('risk_level', 'UNKNOWN')
                    # Adiciona emoji baseado no risco
                    risk_emoji = {
                        'ALTO': '🔴',
                        'MÉDIO': '🟡',
                        'BAIXO': '🟢',
                        'DESCONHECIDO': '⚪'
                    }.get(risk, '⚪')
                    
                    summary.append(
                        f"  {risk_emoji} Porta {port_info.get('port')}: "
                        f"{port_info.get('service', 'Unknown')} [{risk} RISK]"
                    )
        else:
            summary.append("\n✅ Nenhuma porta aberta encontrada, o alvo parece estar bem protegido!")
        
        summary.append("\n" + "="*70 + "\n")
        
        return "\n".join(summary)
    
    def generate_all(self, scan_results, base_filename='scan_report'):
        """
        Gera relatórios em todos os formatos de uma vez
        
        Args:
            scan_results (dict): Resultados do scan
            base_filename (str): Nome base para os arquivos (sem extensão)
            
        Returns:
            dict: Caminhos dos arquivos gerados
        """
        files = {}
        
        # Gera cada formato
        files['json'] = self.generate_json(scan_results, f"{base_filename}.json")
        files['txt'] = self.generate_text(scan_results, f"{base_filename}.txt")
        
        return files