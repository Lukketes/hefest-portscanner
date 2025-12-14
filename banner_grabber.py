import socket
import ssl

class BannerGrabber:
    """Captura banners e informações de serviços em portas abertas"""
    
    def __init__(self, timeout=3):
        """
        Inicializa o banner grabber
        
        Args:
            timeout (int): Timeout para conexão em segundos
        """
        self.timeout = timeout
    
    def grab_banner(self, target, port):
        """
        Tenta capturar o banner de uma porta específica
        
        Args:
            target (str): IP ou hostname
            port (int): Número da porta
            
        Returns:
            str: Banner capturado ou None se falhar
        """
        try:
            # Tenta conexão normal primeiro
            banner = self._grab_standard(target, port)
            
            # Se não conseguiu e é porta SSL comum, tenta SSL
            if not banner and port in [443, 8443, 465, 993, 995]:
                banner = self._grab_ssl(target, port)
            
            return banner
            
        except Exception as e:
            return None
    
    def _grab_standard(self, target, port):
        """
        Captura banner em conexão TCP normal
        
        Args:
            target (str): IP ou hostname
            port (int): Porta
            
        Returns:
            str: Banner ou None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Para alguns serviços (HTTP), precisa enviar requisição
            if port in [80, 8080, 8000, 8888]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
            elif port == 21:  # FTP
                pass  # FTP envia banner automaticamente
            elif port == 25:  # SMTP
                pass  # SMTP envia banner automaticamente
            else:
                # Tenta enviar requisição genérica
                sock.send(b'\r\n')
            
            # Recebe resposta
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except:
            return None
    
    def _grab_ssl(self, target, port):
        """
        Captura banner em conexão SSL/TLS
        
        Args:
            target (str): IP ou hostname
            port (int): Porta
            
        Returns:
            str: Banner ou None
        """
        try:
            # Cria contexto SSL (sem verificação de certificado)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Conecta com SSL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            ssl_sock = context.wrap_socket(sock, server_hostname=target)
            ssl_sock.connect((target, port))
            
            # Envia requisição HTTP se for porta web
            if port in [443, 8443]:
                ssl_sock.send(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
            
            # Recebe resposta
            banner = ssl_sock.recv(1024).decode('utf-8', errors='ignore').strip()
            ssl_sock.close()
            
            return banner if banner else None
            
        except:
            return None
    
    def grab_multiple(self, target, ports):
        """
        Captura banners de múltiplas portas
        
        Args:
            target (str): IP ou hostname
            ports (list): Lista de portas
            
        Returns:
            dict: Dicionário {porta: banner}
        """
        results = {}
        
        for port in ports:
            banner = self.grab_banner(target, port)
            if banner:
                results[port] = banner
        
        return results
    
    @staticmethod
    def extract_service_info(banner):
        """
        Extrai informações úteis do banner
        
        Args:
            banner (str): Banner capturado
            
        Returns:
            dict: Informações extraídas (service, version, etc)
        """
        if not banner:
            return {'service': 'Unknown', 'version': 'Unknown'}
        
        banner_lower = banner.lower()
        info = {'service': 'Unknown', 'version': 'Unknown', 'details': banner[:100]}
        
        # Detecta serviços comuns
        if 'apache' in banner_lower:
            info['service'] = 'Apache HTTP Server'
            # Tenta extrair versão
            if 'apache/' in banner_lower:
                try:
                    version_start = banner_lower.index('apache/') + 7
                    version_end = banner_lower.find(' ', version_start)
                    info['version'] = banner[version_start:version_end if version_end != -1 else version_start+10]
                except:
                    pass
        
        elif 'nginx' in banner_lower:
            info['service'] = 'Nginx HTTP Server'
            if 'nginx/' in banner_lower:
                try:
                    version_start = banner_lower.index('nginx/') + 6
                    version_end = banner_lower.find(' ', version_start)
                    info['version'] = banner[version_start:version_end if version_end != -1 else version_start+10]
                except:
                    pass
        
        elif 'microsoft-iis' in banner_lower:
            info['service'] = 'Microsoft IIS'
            if 'microsoft-iis/' in banner_lower:
                try:
                    version_start = banner_lower.index('microsoft-iis/') + 14
                    version_end = banner_lower.find(' ', version_start)
                    info['version'] = banner[version_start:version_end if version_end != -1 else version_start+10]
                except:
                    pass
        
        elif 'openssh' in banner_lower or 'ssh' in banner_lower:
            info['service'] = 'SSH (OpenSSH)'
            if 'openssh' in banner_lower:
                try:
                    version_start = banner_lower.index('openssh') + 8
                    version_end = banner_lower.find(' ', version_start)
                    info['version'] = banner[version_start:version_end if version_end != -1 else version_start+10]
                except:
                    pass
        
        elif 'ftp' in banner_lower:
            info['service'] = 'FTP Server'
            if 'vsftpd' in banner_lower:
                info['service'] = 'vsftpd'
            elif 'proftpd' in banner_lower:
                info['service'] = 'ProFTPD'
        
        elif 'mysql' in banner_lower:
            info['service'] = 'MySQL Database'
        
        elif 'postgresql' in banner_lower:
            info['service'] = 'PostgreSQL Database'
        
        elif 'smtp' in banner_lower or 'mail' in banner_lower:
            info['service'] = 'SMTP Mail Server'
        
        return info