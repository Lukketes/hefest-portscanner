"""
Service Detector Module

Este módulo identifica serviços rodando em portas, mesmo quando o banner grabbing falha.
Usa um dicionário de portas comuns e seus serviços típicos.
"""

class ServiceDetector:
    """
    Detecta serviços baseado no número da porta e em padrões conhecidos
    
    Útil quando:
    - Banner grabbing falha
    - Serviço não responde com banner
    - Queremos uma identificação rápida
    """
    
    # Dicionário completo de portas conhecidas e seus serviços
    # Formato: porta: (nome_serviço, descrição, protocolo)
    KNOWN_SERVICES = {
        20: ('FTP-DATA', 'FTP Data Transfer', 'TCP'),
        21: ('FTP', 'File Transfer Protocol', 'TCP'),
        22: ('SSH', 'Secure Shell', 'TCP'),
        23: ('TELNET', 'Telnet', 'TCP'),
        25: ('SMTP', 'Simple Mail Transfer Protocol', 'TCP'),
        53: ('DNS', 'Domain Name System', 'TCP/UDP'),
        80: ('HTTP', 'Hypertext Transfer Protocol', 'TCP'),
        110: ('POP3', 'Post Office Protocol v3', 'TCP'),
        111: ('RPCBIND', 'RPC Bind', 'TCP/UDP'),
        135: ('MSRPC', 'Microsoft RPC', 'TCP'),
        139: ('NETBIOS-SSN', 'NetBIOS Session Service', 'TCP'),
        143: ('IMAP', 'Internet Message Access Protocol', 'TCP'),
        443: ('HTTPS', 'HTTP Secure (SSL/TLS)', 'TCP'),
        445: ('SMB', 'Server Message Block', 'TCP'),
        465: ('SMTPS', 'SMTP Secure', 'TCP'),
        587: ('SMTP-SUBMISSION', 'SMTP Submission', 'TCP'),
        993: ('IMAPS', 'IMAP Secure', 'TCP'),
        995: ('POP3S', 'POP3 Secure', 'TCP'),
        1433: ('MSSQL', 'Microsoft SQL Server', 'TCP'),
        1521: ('ORACLE', 'Oracle Database', 'TCP'),
        1723: ('PPTP', 'Point-to-Point Tunneling Protocol', 'TCP'),
        3306: ('MYSQL', 'MySQL Database', 'TCP'),
        3389: ('RDP', 'Remote Desktop Protocol', 'TCP'),
        5432: ('POSTGRESQL', 'PostgreSQL Database', 'TCP'),
        5900: ('VNC', 'Virtual Network Computing', 'TCP'),
        6379: ('REDIS', 'Redis Database', 'TCP'),
        8080: ('HTTP-PROXY', 'HTTP Proxy/Alternative', 'TCP'),
        8443: ('HTTPS-ALT', 'HTTPS Alternative', 'TCP'),
        27017: ('MONGODB', 'MongoDB Database', 'TCP'),
    }
    
    # Categorização de serviços por tipo (útil para relatórios)
    SERVICE_CATEGORIES = {
        'web': [80, 443, 8080, 8443, 8000, 8888],
        'database': [3306, 5432, 1433, 1521, 27017, 6379],
        'mail': [25, 110, 143, 465, 587, 993, 995],
        'remote_access': [22, 23, 3389, 5900],
        'file_transfer': [20, 21, 445],
        'dns': [53],
    }
    
    def __init__(self):
        """Inicializa o detector de serviços"""
        pass
    
    def identify_service(self, port):
        """
        Identifica o serviço baseado no número da porta
        
        Args:
            port (int): Número da porta
            
        Returns:
            dict: Informações do serviço {
                'port': int,
                'service': str,
                'description': str,
                'protocol': str,
                'category': str
            }
        """
        # Busca no dicionário de serviços conhecidos
        if port in self.KNOWN_SERVICES:
            service_name, description, protocol = self.KNOWN_SERVICES[port]
            category = self._get_category(port)
            
            return {
                'port': port,
                'service': service_name,
                'description': description,
                'protocol': protocol,
                'category': category
            }
        else:
            # Porta desconhecida - retorna informação genérica
            return {
                'port': port,
                'service': 'UNKNOWN',
                'description': 'Unknown Service',
                'protocol': 'TCP',
                'category': 'unknown'
            }
    
    def _get_category(self, port):
        """
        Identifica a categoria do serviço baseado na porta
        
        Args:
            port (int): Número da porta
            
        Returns:
            str: Categoria do serviço
        """
        for category, ports in self.SERVICE_CATEGORIES.items():
            if port in ports:
                return category
        return 'other'
    
    def identify_multiple(self, ports):
        """
        Identifica múltiplos serviços de uma vez
        
        Args:
            ports (list): Lista de portas
            
        Returns:
            dict: Dicionário {porta: info_servico}
        """
        results = {}
        for port in ports:
            results[port] = self.identify_service(port)
        return results
    
    def get_risk_level(self, port):
        """
        Avalia o nível de risco de uma porta estar exposta
        
        Args:
            port (int): Número da porta
            
        Returns:
            str: 'HIGH', 'MEDIUM', 'LOW'
        """
        # Portas de alto risco (acesso remoto, bancos de dados expostos)
        high_risk = [23, 3389, 5900, 1433, 3306, 5432, 27017, 6379]
        
        # Portas de médio risco (serviços que podem ser explorados)
        medium_risk = [21, 25, 110, 143, 445, 1521, 8080]
        
        # Portas de baixo risco (serviços comuns e geralmente seguros)
        low_risk = [80, 443, 22, 53]
        
        if port in high_risk:
            return 'HIGH'
        elif port in medium_risk:
            return 'MEDIUM'
        elif port in low_risk:
            return 'LOW'
        else:
            return 'UNKNOWN'
    
    def get_security_recommendations(self, port):
        """
        Retorna recomendações de segurança para uma porta específica
        
        Args:
            port (int): Número da porta
            
        Returns:
            list: Lista de recomendações
        """
        recommendations = {
            21: ['Considere usar SFTP (porta 22) ao invés de FTP', 
                 'FTP transmite credenciais em texto claro'],
            22: ['Use autenticação por chave SSH', 
                 'Desabilite login root direto'],
            23: ['NUNCA use Telnet - use SSH (porta 22)', 
                 'Telnet é completamente inseguro'],
            3306: ['MySQL não deve estar exposto à internet', 
                   'Use firewall para restringir acesso'],
            3389: ['RDP é alvo frequente de ataques', 
                   'Use VPN ou restrinja IPs permitidos',
                   'Ative autenticação de dois fatores'],
            5900: ['VNC deve ser protegido com senha forte', 
                   'Considere usar túnel SSH'],
        }
        
        # Retorna recomendações específicas ou genéricas
        if port in recommendations:
            return recommendations[port]
        else:
            return ['Verifique se este serviço realmente precisa estar exposto']