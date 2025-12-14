import socket
import threading
from queue import Queue
from datetime import datetime

class PortScanner:
    """Scanner de portas TCP com suporte a multi-threading"""
    
    # Portas mais comuns para scan rápido
    COMMON_PORTS = [
        20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    ]
    
    def __init__(self, target, timeout=1, threads=100):
        """
        Inicializa o scanner
        
        Args:
            target (str): IP ou hostname do alvo
            timeout (int): Timeout para cada conexão em segundos
            threads (int): Número de threads para scanning paralelo
        """
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.lock = threading.Lock()
        
        # Resolve hostname para IP
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Não foi possível resolver o hostname: {target}")
    
    def scan_port(self, port):
        """
        Tenta conectar em uma porta específica
        
        Args:
            port (int): Número da porta
            
        Returns:
            bool: True se porta estiver aberta, False caso contrário
        """
        try:
            # Cria socket TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Tenta conectar
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            # result == 0 significa conexão bem sucedida (porta aberta)
            return result == 0
            
        except socket.error:
            return False
    
    def worker(self, queue, progress_callback=None):
        """
        Worker thread que processa portas da queue
        
        Args:
            queue (Queue): Queue com portas para escanear
            progress_callback (callable): Função para atualizar progresso
        """
        while not queue.empty():
            port = queue.get()
            
            if self.scan_port(port):
                with self.lock:
                    self.open_ports.append(port)
            
            if progress_callback:
                progress_callback()
            
            queue.task_done()
    
    def scan(self, ports=None, progress_callback=None):
        """
        Executa o scan nas portas especificadas
        
        Args:
            ports (list): Lista de portas ou None para portas comuns
            progress_callback (callable): Função chamada a cada porta escaneada
            
        Returns:
            dict: Resultados do scan com informações
        """
        if ports is None:
            ports = self.COMMON_PORTS
        
        # Prepara a queue com todas as portas
        queue = Queue()
        for port in ports:
            queue.put(port)
        
        # Inicia timestamp
        start_time = datetime.now()
        
        # Cria e inicia threads
        threads_list = []
        num_threads = min(self.threads, len(ports))
        
        for _ in range(num_threads):
            thread = threading.Thread(target=self.worker, args=(queue, progress_callback))
            thread.daemon = True
            thread.start()
            threads_list.append(thread)
        
        # Aguarda todas as threads terminarem
        queue.join()
        
        # Calcula tempo total
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Ordena portas abertas
        self.open_ports.sort()
        
        return {
            'target': self.target,
            'target_ip': self.target_ip,
            'scan_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': duration,
            'ports_scanned': len(ports),
            'open_ports': self.open_ports,
            'total_open': len(self.open_ports)
        }
    
    @staticmethod
    def scan_range(target, start_port, end_port, timeout=1, threads=100, progress_callback=None):
        """
        Método auxiliar para escanear um range de portas
        
        Args:
            target (str): IP ou hostname
            start_port (int): Porta inicial
            end_port (int): Porta final
            timeout (int): Timeout em segundos
            threads (int): Número de threads
            progress_callback (callable): Callback de progresso
            
        Returns:
            dict: Resultados do scan
        """
        scanner = PortScanner(target, timeout, threads)
        ports = list(range(start_port, end_port + 1))
        return scanner.scan(ports, progress_callback)
    
    @staticmethod
    def scan_common(target, timeout=1, threads=100, progress_callback=None):
        """
        Método auxiliar para escanear portas comuns
        
        Args:
            target (str): IP ou hostname
            timeout (int): Timeout em segundos
            threads (int): Número de threads
            progress_callback (callable): Callback de progresso
            
        Returns:
            dict: Resultados do scan
        """
        scanner = PortScanner(target, timeout, threads)
        return scanner.scan(progress_callback=progress_callback)